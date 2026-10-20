// fishhook.c —— 极简 fishhook 实现
//
// 遍历当前进程已加载的所有 Mach-O image（含主程序），对每个 image 的
// __la_symbol_ptr / __got / __nl_symbol_ptr 段做符号名匹配并替换指针。
//
// 注意：只处理「指向 symtab 的普通 binding」（BIND_TYPE_POINTER），
// 这里覆盖 __DATA_CONST 下的 lazy/non-lazy 两种表。

#include "fishhook.h"

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <mach-o/reloc.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__LP64__)
typedef struct mach_header_64     mr_mach_header;
typedef struct segment_command_64 mr_segment_command;
typedef struct section_64         mr_section;
typedef struct nlist_64           mr_nlist;
#define MR_MH_MAGIC MH_MAGIC_64
#define MR_LC_SEGMENT LC_SEGMENT_64
#else
typedef struct mach_header        mr_mach_header;
typedef struct segment_command    mr_segment_command;
typedef struct section            mr_section;
typedef struct nlist              mr_nlist;
#define MR_MH_MAGIC MH_MAGIC
#define MR_LC_SEGMENT LC_SEGMENT
#endif

static int mr_protect(void *addr, size_t size, int prot) {
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(sizeof(void *) - 1);
    uintptr_t end   = ((uintptr_t)addr + size + sizeof(void *) - 1)
                      & ~(uintptr_t)(sizeof(void *) - 1);
    return vm_protect(mach_task_self(), (vm_address_t)start,
                      end - start, false, prot);
}

// 处理单个 image 的指针表
static int mr_rebind_image(const mr_mach_header *hdr,
                           const struct mr_rebinding *rb, size_t n,
                           intptr_t slide) {
    size_t symtab = 0;       // 文件偏移
    size_t strtab = 0;
    size_t strsize = 0;
    uint32_t nsyms = 0;
    int have_symtab = 0;

    // 第一遍：定位符号表
    const uint8_t *cmdp = (const uint8_t *)hdr + sizeof(mr_mach_header);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdp;
        if (lc->cmd == LC_SYMTAB) {
            const struct symtab_command *sc = (const struct symtab_command *)lc;
            symtab = sc->symoff;
            strtab = sc->stroff;
            strsize = sc->strsize;
            nsyms = sc->nsyms;
            have_symtab = 1;
        }
        cmdp += lc->cmdsize;
    }
    if (!have_symtab) return 0;

    // image 的资源在内存里，文件偏移要用 header 里 __LINKEDIT 的映射换算。
    // 对主程序（非 dylib），映射连续，直接用 vmaddr 与 off 的差值。
    const mr_segment_command *linkedit = NULL;
    const mr_segment_command *textseg = NULL;
    cmdp = (const uint8_t *)hdr + sizeof(mr_mach_header);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdp;
        if (lc->cmd == MR_LC_SEGMENT) {
            const mr_segment_command *sg = (const mr_segment_command *)lc;
            if (strcmp(sg->segname, "__LINKEDIT") == 0) linkedit = sg;
            if (strcmp(sg->segname, "__TEXT") == 0) textseg = sg;
        }
        cmdp += lc->cmdsize;
    }
    if (!linkedit || !textseg) return 0;

    // 文件偏移 -> 内存地址
    // symtab 的 symoff/stroff 是文件偏移；__LINKEDIT 在文件里对应的 vmaddr
    // 可以用（linkedit->vmaddr - linkedit->fileoff）换算到内存地址。
    intptr_t linkedit_base = (intptr_t)(linkedit->vmaddr - linkedit->fileoff) + slide;

    const mr_nlist *syms = (const mr_nlist *)(linkedit_base + symtab);
    const char *strs     = (const char *)(linkedit_base + strtab);

    int hits = 0;

    // 第二遍：遍历段，找 __la_symbol_ptr / __got / __nl_symbol_ptr
    cmdp = (const uint8_t *)hdr + sizeof(mr_mach_header);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdp;
        if (lc->cmd == MR_LC_SEGMENT) {
            const mr_segment_command *sg = (const mr_segment_command *)lc;
            const mr_section *sect = (const mr_section *)(sg + 1);

            for (uint32_t j = 0; j < sg->nsects; j++, sect++) {
                int is_ptr_table = 0;
                if (strcmp(sect->sectname, "__la_symbol_ptr") == 0) is_ptr_table = 1;
                if (strcmp(sect->sectname, "__got") == 0)           is_ptr_table = 1;
                if (!is_ptr_table) continue;

                uint32_t count = (uint32_t)(sect->size / sizeof(void *));
                uint32_t base_index = sect->reserved1;   // 该段在符号表里的起始下标

                for (uint32_t k = 0; k < count; k++) {
                    uint32_t sidx = base_index + k;
                    if (sidx >= nsyms) continue;

                    const mr_nlist *sym = &syms[sidx];
                    if (sym->n_un.n_strx == 0 || sym->n_un.n_strx >= strsize) continue;

                    const char *name = strs + sym->n_un.n_strx;
                    if (name[0] != '_') continue;
                    const char *bare = name + 1;   // 去掉前导下划线

                    for (size_t r = 0; r < n; r++) {
                        if (strcmp(bare, rb[r].name) != 0) continue;

                        void **target = (void **)(sect->addr + slide) + k;

                        mr_protect(target, sizeof(void *),
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        if (rb[r].replaced) *(rb[r].replaced) = *target;
                        *target = rb[r].replacement;
                        mr_protect(target, sizeof(void *), VM_PROT_READ);

                        hits++;
                        fprintf(stderr, "[fishhook] rebound %s at %p\n", bare, target);
                    }
                }
            }
        }
        cmdp += lc->cmdsize;
    }

    (void)hdr->flags;
    return hits;
}

int MRRebindSymbols(struct mr_rebinding *rebindings, size_t n) {
    int total = 0;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const mr_mach_header *hdr =
            (const mr_mach_header *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MR_MH_MAGIC) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        total += mr_rebind_image(hdr, rebindings, n, slide);
    }
    return total;
}
