// MRProbe — 只读探针：确认 connect GOT 槽在运行时的真实值
//
// 不改任何东西，只读 + 打印。
// 输出到 /var/mobile/Documents/MRProbe.log
//
// 关键地址（静态分析得出，基于 DespicableMe 10.5.0c arm64）：
//   __DATA,__got          addr=0x103660000 size=0x2ef0  reserved1=2035
//   __DATA,__la_symbol_ptr addr=0x103662ef0 size=0x3e38 reserved1=3537
//   _connect      undefined#2607 → __la_symbol_ptr 槽索引 1277 → VA 0x1036656d8
//   _getaddrinfo  undefined#2708 → __la_symbol_ptr 槽索引 1376 → VA 0x1036659f0

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <pthread.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static char gLogPath[512] = {0};
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static void POpen(void) {
    const char *c[] = {"/var/mobile/Documents/MRProbe.log",
                       "/var/mobile/Media/MRProbe.log",
                       "/var/tmp/MRProbe.log", "/tmp/MRProbe.log", NULL};
    for (int i = 0; c[i]; i++) {
        FILE *f = fopen(c[i], "a");
        if (f) { fclose(f); strlcpy(gLogPath, c[i], sizeof(gLogPath)); return; }
    }
    NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (d) {
        NSString *p = [d stringByAppendingPathComponent:@"MRProbe.log"];
        strlcpy(gLogPath, [p UTF8String], sizeof(gLogPath));
        FILE *f = fopen(gLogPath, "a"); if (f) fclose(f);
    }
}

static void PLog(const char *fmt, ...) {
    char m[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(m, sizeof(m), fmt, ap); va_end(ap);
    pthread_mutex_lock(&gLock);
    if (gLogPath[0]) {
        FILE *f = fopen(gLogPath, "a");
        if (f) { fprintf(f, "%s\n", m); fclose(f); }
    }
    pthread_mutex_unlock(&gLock);
}

// 打印一个槽的信息
static void DumpSlot(const char *label, uintptr_t slide, uint64_t staticVA) {
    void **slot = (void **)(staticVA + slide);
    void *val = *slot;
    Dl_info di; memset(&di, 0, sizeof(di));
    const char *sym = "?";
    const char *img = "?";
    if (val && dladdr(val, &di)) {
        if (di.dli_sname) sym = di.dli_sname;
        if (di.dli_fname) img = di.dli_fname;
    }
    PLog("%-14s VA=%p  slot=%p  value=%p  sym=%s  img=%s",
         label, (void *)staticVA, slot, val, sym, img);
}

__attribute__((constructor))
static void MRProbeInit(void) {
    POpen();

    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(0);

    PLog("==== MRProbe ====");
    PLog("bundle = %s", [[[NSBundle mainBundle] bundleIdentifier] UTF8String]);
    PLog("hdr    = %p   slide = 0x%lx", hdr, (unsigned long)slide);
    PLog("sysver = %s", [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String]);
    PLog("日志   = %s", gLogPath);

    // fixup 格式
    BOOL chained = NO;
    {
        const uint8_t *q = (const uint8_t *)hdr + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)q;
            if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) chained = YES;
            q += lc->cmdsize;
        }
    }
    PLog("chained_fixups = %s", chained ? "YES" : "NO");

    // dlsym 的对照值
    PLog("dlsym connect     = %p", dlsym(RTLD_DEFAULT, "connect"));
    PLog("dlsym getaddrinfo = %p", dlsym(RTLD_DEFAULT, "getaddrinfo"));

    // 静态分析得出的槽
    DumpSlot("connect",     slide, 0x1036656d8ULL);
    DumpSlot("getaddrinfo", slide, 0x1036659f0ULL);

    // 顺便把 __la_symbol_ptr 整个段扫一遍，看有多少槽能反查出真实符号
    // __DATA,__la_symbol_ptr addr=0x103662ef0 size=0x3e38
    {
        void **base = (void **)(0x103662ef0ULL + slide);
        size_t n = 0x3e38 / 8;
        int named = 0, unnamed = 0, nullc = 0;
        int foundConnect = -1, foundGai = -1;
        const char *connFile = NULL, *gaiFile = NULL;
        for (size_t i = 0; i < n; i++) {
            void *v = base[i];
            if (!v) { nullc++; continue; }
            Dl_info di; memset(&di, 0, sizeof(di));
            if (dladdr(v, &di) && di.dli_sname) {
                named++;
                if (!strcmp(di.dli_sname, "connect")) {
                    foundConnect = (int)i;
                    if (di.dli_fname) connFile = di.dli_fname;
                }
                if (!strcmp(di.dli_sname, "getaddrinfo")) {
                    foundGai = (int)i;
                    if (di.dli_fname) gaiFile = di.dli_fname;
                }
            } else {
                unnamed++;
            }
        }
        PLog("__la_symbol_ptr 扫描: 共 %zu 槽  有名 %d  无名 %d  空 %d",
             n, named, unnamed, nullc);
        PLog("  其中 connect 在索引 %d (预期 1277)，来自 %s",
             foundConnect, connFile ? connFile : "?");
        PLog("  其中 getaddrinfo 在索引 %d (预期 1376)，来自 %s",
             foundGai, gaiFile ? gaiFile : "?");
    }

    // 也扫 __got
    {
        void **base = (void **)(0x103660000ULL + slide);
        size_t n = 0x2ef0 / 8;
        int named = 0, unnamed = 0, nullc = 0;
        int foundConnect = -1;
        for (size_t i = 0; i < n; i++) {
            void *v = base[i];
            if (!v) { nullc++; continue; }
            Dl_info di; memset(&di, 0, sizeof(di));
            if (dladdr(v, &di) && di.dli_sname) {
                named++;
                if (!strcmp(di.dli_sname, "connect")) foundConnect = (int)i;
            } else unnamed++;
        }
        PLog("__got 扫描: 共 %zu 槽  有名 %d  无名 %d  空 %d  connect 索引 %d",
             n, named, unnamed, nullc, foundConnect);
    }

    PLog("==== 探针结束 ====");
}
