// fishhook.h —— 极简版 fishhook（改 Mach-O 导入表，不需要任何运行时 hook 库）
//
// 原理：dyld 把主程序里每个「动态导入函数」的地址记录在 __la_symbol_ptr（懒绑定）
// 或 __got（非懒绑定）里。开局的指针指向 binder stub，第一次调用后写回真实地址。
// 我们只需要遍历这些指针表，把名字匹配的那个指针换成自己的函数，就完成拦截。
//
// 相比 MSHookFunction（改函数体指令）：不需要 Substrate/ElleKit，纯数据操作，
// 越狱/巨魔/未越狱只要 dylib 能被加载就生效。

#ifndef MR_FISHHOOK_H
#define MR_FISHHOOK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mr_rebinding {
    const char *name;
    void       *replacement;
    void      **replaced;
};

int MRRebindSymbols(struct mr_rebinding *rebindings, size_t n);

#ifdef __cplusplus
}
#endif

#endif
