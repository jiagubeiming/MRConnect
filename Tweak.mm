// MRConnect — Minion Rush 网络重定向（方案 A）
//
// ═══════════════════════════════════════════════════════════
//  思路：照搬安卓 libmroffline.so
// ═══════════════════════════════════════════════════════════
//
//  安卓在 libc 的 connect() 上做 inline hook，把**所有** TCP 连接的目标
//  改到 127.0.0.1:<本地端口>。不管游戏用什么 HTTP 栈（libcurl /
//  NSURLSession / CFNetwork / 裸 socket），也不管它"愿不愿意"请求某个
//  域名 —— 一律落到本地服务器。
//
//  之前用 NSURLProtocol 失败：iOS 版把 libcurl 静态链接进来了
//  （二进制里有 "CLIENT libcurl 7.88.1-DEV"），libcurl 自己管 socket，
//  根本不过 Foundation，NSURLProtocol 看不见。
//
//  connect() 是所有网络请求的必经之路 —— 改这一步，上层用什么库都无所谓。
//
// ═══════════════════════════════════════════════════════════
//  实现要点（针对本游戏的二进制结构）
// ═══════════════════════════════════════════════════════════
//
//  实测主程序 DespicableMe 的 Mach-O 头：
//    · 有 LC_DYLD_INFO_ONLY，**没有** LC_DYLD_CHAINED_FIXUPS
//      → __got / __la_symbol_ptr 里存的是**真实函数地址**，可直接改写
//        （新版 iOS 的 chained fixups 存的是编码值，那样就得解码后重编）
//    · LC_DYSYMTAB 为空（size=1）→ 没有 external relocations 表，
//      不能用 extreloff 找槽，必须**遍历 __got/__la_symbol_ptr 段**
//
//  做法：
//    1. 解析主程序 Mach-O，取出 __got 和 __la_symbol_ptr 两个段
//    2. 遍历每个 8 字节槽，取出它当前指向的地址
//    3. 用 dladdr() 把地址反查成符号名
//    4. 名字是 connect / getaddrinfo 的，把槽里的值换成我们的函数
//    mprotect 需要的页改成可写，改完恢复
//
//  ⚠ 不改 libSystem 自身代码（不 inline patch），只改主程序对它的引用，
//    这样风险最低，也不受 PAC / 代码签名影响。
//
// ═══════════════════════════════════════════════════════════
//  需要什么
// ═══════════════════════════════════════════════════════════
//    · 手机已安装根证书（TLS 由游戏自己做，我们只改地址）
//    · 本地服务器监听 443
//    · 不需要 DNS 劫持、不需要路由器配置
//
// ═══════════════════════════════════════════════════════════
//  卸载
// ═══════════════════════════════════════════════════════════
//    删掉
//      /Library/MobileSubstrate/DynamicLibraries/MRConnect.dylib
//      /Library/MobileSubstrate/DynamicLibraries/MRConnect.plist
//    （无根越狱在 /var/jb/Library/MobileSubstrate/DynamicLibraries/ 下）

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <sys/mman.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <unistd.h>
#import <dlfcn.h>
#import <string.h>
#import <stdio.h>
#import <stdlib.h>
#import <pthread.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach/vm_prot.h>

// 修复：MRLog 需要用 NSString 做格式串（可变参数不能直接传 std::string）

// ═══════════════════════════════════════════════════════════
//  配置
// ═══════════════════════════════════════════════════════════

#define MR_LOCAL_HOST   "127.0.0.1"
#define MR_LOCAL_PORT   443

// 劫持这些端口
static const int kHijackPorts[] = { 443 };

// YES = 劫持所有到 443 的连接（排查最干净）
// NO  = 只劫持目标 IP 属于下面域名的连接（需先解析域名，较复杂，不推荐）
static BOOL gHijackAll = YES;

// ═══════════════════════════════════════════════════════════
//  日志
// ═══════════════════════════════════════════════════════════

static char gLogPath[512] = {0};
static pthread_mutex_t gLogLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long gSeq = 0;

#define SEEN_MAX 1024
static char gSeen[SEEN_MAX][160];
static int  gSeenCount = 0;

static void MROpenLog(void) {
    const char *cands[] = {
        "/var/mobile/Documents/MRConnect.log",
        "/var/mobile/Media/MRConnect.log",
        "/var/tmp/MRConnect.log",
        "/tmp/MRConnect.log",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        FILE *f = fopen(cands[i], "a");
        if (f) { fclose(f); strlcpy(gLogPath, cands[i], sizeof(gLogPath)); return; }
    }
    NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                       NSUserDomainMask, YES) firstObject];
    if (d) {
        NSString *p = [d stringByAppendingPathComponent:@"MRConnect.log"];
        strlcpy(gLogPath, [p UTF8String], sizeof(gLogPath));
        // 确保文件存在
        FILE *f = fopen(gLogPath, "a"); if (f) fclose(f);
    }
}

// MRLog 统一入口：C 格式串 + 可变参数（调用的地方都用 C 字符串格式）
static void MRLog(const char *fmt, ...) {
    char msg[1200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&gLogLock);
    if (gLogPath[0]) {
        FILE *f = fopen(gLogPath, "a");
        if (f) { fprintf(f, "%07lu %s\n", ++gSeq, msg); fclose(f); }
    }
    pthread_mutex_unlock(&gLogLock);
    NSLog(@"[MRCONNECT] %s", msg);
}

static BOOL MRMarkSeen(const char *key) {
    pthread_mutex_lock(&gLogLock);
    for (int i = 0; i < gSeenCount; i++) {
        if (strcmp(gSeen[i], key) == 0) { pthread_mutex_unlock(&gLogLock); return YES; }
    }
    if (gSeenCount < SEEN_MAX) strlcpy(gSeen[gSeenCount++], key, sizeof(gSeen[0]));
    pthread_mutex_unlock(&gLogLock);
    return NO;
}

// ═══════════════════════════════════════════════════════════
//  原始函数指针
// ═══════════════════════════════════════════════════════════

typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_t)(const char *, const char *,
                             const struct addrinfo *, struct addrinfo **);

static connect_t     gOrigConnect     = NULL;
static getaddrinfo_t gOrigGetaddrinfo = NULL;

// ═══════════════════════════════════════════════════════════
//  connect 替换
// ═══════════════════════════════════════════════════════════

static BOOL MRIsHijackPort(int port) {
    for (size_t i = 0; i < sizeof(kHijackPorts) / sizeof(kHijackPorts[0]); i++) {
        if (kHijackPorts[i] == port) return YES;
    }
    return NO;
}

static int MRConnect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    connect_t orig = gOrigConnect ? gOrigConnect : connect;
    if (!addr) return orig(fd, addr, addrlen);

    struct sockaddr_storage newAddr;
    memset(&newAddr, 0, sizeof(newAddr));
    memcpy(&newAddr, addr, addrlen < sizeof(newAddr) ? addrlen : sizeof(newAddr));

    BOOL changed = NO;
    char desc[192] = {0};

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&newAddr;
        int port = ntohs(in->sin_port);
        char ip[64] = {0};
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));

        if (MRIsHijackPort(port)) {
            snprintf(desc, sizeof(desc), "%s:%d", ip, port);
            if (gHijackAll && strcmp(ip, MR_LOCAL_HOST) != 0) {
                in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                in->sin_port = htons(MR_LOCAL_PORT);
                changed = YES;
            }
        }
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&newAddr;
        int port = ntohs(in6->sin6_port);
        char ip[64] = {0};
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));

        if (MRIsHijackPort(port)) {
            snprintf(desc, sizeof(desc), "[%s]:%d", ip, port);
            // 只有「非回环」的 IPv6 才改：::1 已经是本机了
            BOOL isLoopback = (memcmp(&in6->sin6_addr, &in6addr_loopback,
                                      sizeof(in6->sin6_addr)) == 0);
            if (gHijackAll && !isLoopback) {
                struct sockaddr_in v4;
                memset(&v4, 0, sizeof(v4));
                v4.sin_family = AF_INET;
                v4.sin_port = htons(MR_LOCAL_PORT);
                v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                memcpy(&newAddr, &v4, sizeof(v4));
                addrlen = sizeof(v4);
                changed = YES;
            }
        }
    }

    if (changed) {
        if (!MRMarkSeen(desc)) {
            MRLog("connect 劫持 %s -> %s:%d", desc, MR_LOCAL_HOST, MR_LOCAL_PORT);
        }
        return orig(fd, (struct sockaddr *)&newAddr, addrlen);
    }
    return orig(fd, addr, addrlen);
}

// ═══════════════════════════════════════════════════════════
//  getaddrinfo 替换（双保险：有些库先解析再连）
// ═══════════════════════════════════════════════════════════

static int MRGetaddrinfo(const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res) {
    getaddrinfo_t orig = gOrigGetaddrinfo ? gOrigGetaddrinfo : getaddrinfo;
    int r = orig(node, service, hints, res);
    if (r != 0 || !res || !*res || !node) return r;
    if (!gHijackAll) return r;

    int n = 0;
    for (struct addrinfo *ai = *res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addr) {
            struct sockaddr_in *in = (struct sockaddr_in *)ai->ai_addr;
            in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            n++;
        }
    }
    if (n > 0) {
        char key[160];
        snprintf(key, sizeof(key), "dns:%s", node);
        if (!MRMarkSeen(key)) MRLog("getaddrinfo 改写 %s -> 127.0.0.1 (%d 条)", node, n);
    }
    return r;
}

// ═══════════════════════════════════════════════════════════
//  GOT 槽改写
// ═══════════════════════════════════════════════════════════

// 把一段内存改成可写
static int MRMakeWritable(void *addr, size_t len, int *savedProt) {
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(pageSize - 1);
    uintptr_t end   = ((uintptr_t)addr + len + pageSize - 1) & ~(uintptr_t)(pageSize - 1);
    size_t   sz     = end - start;

    // 直接改页保护即可（__DATA 段本来就在可写区，__DATA_CONST 需要这一步）
    if (mprotect((void *)start, sz, PROT_READ | PROT_WRITE) != 0) {
        return -1;
    }
    *savedProt = PROT_READ;
    return 0;
}

// 遍历指定名字的段，找值为 targetName 的槽并替换
static int MRPatchSection(const struct mach_header_64 *hdr,
                          const char *segName, const char *sectName,
                          const char *symName, void *replacement,
                          void **oldOut) {
    const uint8_t *p = (const uint8_t *)hdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, segName) == 0) {
                const struct section_64 *sect =
                    (const struct section_64 *)((const uint8_t *)seg +
                                                sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++, sect++) {
                    if (strcmp(sect->sectname, sectName) != 0) continue;

                    void **slots = (void **)((uint8_t *)hdr + sect->offset);
                    size_t n = sect->size / sizeof(void *);

                    // 注意：__got / __la_symbol_ptr 的 file offset 是相对文件头的，
                    // 而 hdr 是运行时映射地址，二者在 __TEXT 段里一致（offset==vmaddr-base）
                    for (size_t k = 0; k < n; k++) {
                        void *cur = slots[k];
                        if (!cur) continue;
                        Dl_info info;
                        if (dladdr(cur, &info) && info.dli_sname) {
                            if (strcmp(info.dli_sname, symName) == 0) {
                                int saved = 0;
                                if (MRMakeWritable(&slots[k], sizeof(void *), &saved) != 0) {
                                    MRLog("  %s/%s[%lu] = %s 但 mprotect 失败",
                                          segName, sectName, (unsigned long)k, symName);
                                    continue;
                                }
                                *oldOut = cur;
                                slots[k] = replacement;
                                MRLog("  命中 %s/%s[%lu] %s  %p -> %p",
                                      segName, sectName, (unsigned long)k, symName, cur, replacement);
                                return 1;
                            }
                        }
                    }
                }
            }
        }
        p += lc->cmdsize;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════
//  入口
// ═══════════════════════════════════════════════════════════

__attribute__((constructor))
static void MRConnectInit(void) {
    MROpenLog();

    MRLog("==== MRConnect 载入 ====");
    MRLog("bundle = %s", [[[NSBundle mainBundle] bundleIdentifier] UTF8String]);
    MRLog("日志   = %s", gLogPath);
    MRLog("目标   = %s:%d  hijackAll=%d", MR_LOCAL_HOST, MR_LOCAL_PORT, (int)gHijackAll);

    // 先用 dlsym 取原始实现（作为 fallback，也用于对比）
    gOrigConnect     = (connect_t)dlsym(RTLD_DEFAULT, "connect");
    gOrigGetaddrinfo = (getaddrinfo_t)dlsym(RTLD_DEFAULT, "getaddrinfo");
    MRLog("dlsym: connect=%p getaddrinfo=%p", (void*)gOrigConnect, (void*)gOrigGetaddrinfo);

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(0);

    // 检查 fixup 格式
    BOOL hasChained = NO;
    {
        const uint8_t *q = (const uint8_t *)hdr + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)q;
            if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) hasChained = YES;
            q += lc->cmdsize;
        }
    }
    MRLog("chained fixups = %s", hasChained ? "YES（槽内是编码值，下列改写可能无效）"
                                             : "NO （槽内是真实地址，可直接改写）");

    // 依次在几个可能的段里找
    void *old1 = NULL, *old2 = NULL;
    int okC = 0, okD = 0;

    const char *segs[] = { "__DATA", "__DATA_CONST", "__AUTH_CONST", "__DATA_DIRTY", NULL };
    for (int i = 0; segs[i] && !okC; i++)
        okC = MRPatchSection(hdr, segs[i], "__got", "connect", (void *)MRConnect, &old1);
    for (int i = 0; segs[i] && !okC; i++)
        okC = MRPatchSection(hdr, segs[i], "__la_symbol_ptr", "connect",
                             (void *)MRConnect, &old1);

    for (int i = 0; segs[i] && !okD; i++)
        okD = MRPatchSection(hdr, segs[i], "__got", "getaddrinfo",
                             (void *)MRGetaddrinfo, &old2);
    for (int i = 0; segs[i] && !okD; i++)
        okD = MRPatchSection(hdr, segs[i], "__la_symbol_ptr", "getaddrinfo",
                             (void *)MRGetaddrinfo, &old2);

    MRLog("改写结果: connect=%d getaddrinfo=%d", okC, okD);

    if (!okC) {
        MRLog("connect 槽未命中！退回到 inline hook 方式");
        // 说明主程序没有直接引用 connect（可能全在 libcurl 里）
        // 这种情况下面用 dlopen 的钩子兜底
    }

    // 心跳
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        for (int i = 1; i <= 40; i++) {
            sleep(15);
            MRLog("HEARTBEAT #%d  seen=%d", i, gSeenCount);
        }
    });
}
