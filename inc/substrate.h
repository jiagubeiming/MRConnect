// substrate.h —— MSHookFunction 最小声明（不依赖 theos）
//
// 为什么不用 theos/headers：它仓库里的 substrate.h 只是 `#include <CydiaSubstrate/CydiaSubstrate.h>`，
// 而那个子路径并不存在（jsdelivr 列出的 830 个文件里没有任何 CydiaSubstrate 目录），
// 官方 CI 一直拿不到真头文件。这里手写声明，等价于官方头里 MSHookFunction 的部分。
//
// MSHookFunction 在运行时由 Substrate / libhooker / ElleKit / Choicy 等注入库
// 通过 dyld 提供的符号解析，编译期只需要知道签名。

#ifndef MR_SUBSTRATE_MIN_H
#define MR_SUBSTRATE_MIN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// void MSHookFunction(void *symbol, void *replace, void **result);
//   symbol  —— 要钩的函数地址
//   replace —— 我们的替代实现
//   result  —— 输出：原函数跳板地址（调用它等于调用原函数）
typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);

// 运行时从已加载的注入库里取 MSHookFunction。
// 因为编译期没有 libsubstrate 可链接，只能用 dlsym 在运行时解析。
void *MRFindSubstrateSymbol(const char *name);

#ifdef __cplusplus
}
#endif

#endif // MR_SUBSTRATE_MIN_H
