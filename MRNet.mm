// MRNet.mm —— 进程内网络拦截（安卓 libmroffline.so offline_hook_connect 的 iOS 同构版）
//
// 两条路都试，优先级：
//   1) MSHookFunction（有 Substrate/ElleKit 时最可靠，改函数体指令）
//   2) fishhook（改 Mach-O 导入表，不需要任何运行时库 → 巨魔/未越狱也能用）
//
// 只要任意一条成功，就把到 gameloft 的连接改向本地假服务器。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>
#import <strings.h>
#import <stdarg.h>
#import <stdio.h>
#import <stdlib.h>
#import <time.h>
#import <unistd.h>
#import <sys/socket.h>
#import <netinet/in.h>
#include <netinet/in6.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <pthread.h>

#include "substrate.h"
#include "fishhook.h"

// ── 配置 ─────────────────────────────────────────────────────────────
static const char *kLocalHost = "192.168.123.83";
static const int   kLocalPort = 443;
static const int   kHookAnyPort = 1;

static const char *kDomains[] = {
    "gameloft.com", "gameloft.net", "gameloft.org", NULL
};

// ── 日志 ─────────────────────────────────────────────────────────────
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;
static char gLogPath[512] = {0};

static void logOpen(void) {
    const char *cands[] = {
        "/var/mobile/Documents/MRNet.log",
        "/var/mobile/Media/MRNet.log",
        "/var/tmp/MRNet.log",
        "/tmp/MRNet.log",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        FILE *f = fopen(cands[i], "a");
        if (f) { fclose(f); strncpy(gLogPath, cands[i], sizeof(gLogPath) - 1); return; }
    }
    NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (d) snprintf(gLogPath, sizeof(gLogPath), "%s/MRNet.log", [d UTF8String]);
}

static void MRLog(const char *fmt, ...) {
    if (!gLogPath[0]) return;
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&gLock);
    FILE *f = fopen(gLogPath, "a");
    if (f) {
        time_t t = time(NULL);
        struct tm tmv;
        localtime_r(&t, &tmv);
        fprintf(f, "%02d:%02d:%02d %s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, buf);
        fflush(f);
        fclose(f);
    }
    pthread_mutex_unlock(&gLock);
}

// ── 域名判定 ─────────────────────────────────────────────────────────
static int isGameloft(const char *host) {
    if (!host || !*host) return 0;
    if (strcmp(host, "127.0.0.1") == 0) return 0;
    if (strcmp(host, kLocalHost) == 0) return 0;
    for (int i = 0; kDomains[i]; i++) {
        size_t hl = strlen(host), dl = strlen(kDomains[i]);
        if (hl >= dl && strcasecmp(host + hl - dl, kDomains[i]) == 0) return 1;
    }
    return 0;
}

// ── 原函数跳板 ───────────────────────────────────────────────────────
static int  (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int  (*orig_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *, struct addrinfo **);
static struct hostent *(*orig_gethostbyname)(const char *);

// ── connect 包装 ─────────────────────────────────────────────────────
static int MRConnect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        int port = 0;
        if (addr->sa_family == AF_INET) {
            port = ntohs(((const struct sockaddr_in *)addr)->sin_port);
        } else {
            port = ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
        }

        if (kHookAnyPort || port == 443 || port == 80) {
            char ip[64] = "?";
            if (addr->sa_family == AF_INET) {
                inet_ntop(AF_INET, &((const struct sockaddr_in *)addr)->sin_addr, ip, sizeof(ip));
            } else {
                inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)addr)->sin6_addr, ip, sizeof(ip));
            }

            struct sockaddr_in na;
            memset(&na, 0, sizeof(na));
            na.sin_family = AF_INET;
            na.sin_port = htons(kLocalPort);
            inet_pton(AF_INET, kLocalHost, &na.sin_addr);
            na.sin_len = sizeof(na);

            MRLog("REDIR %s:%d -> %s:%d", ip, port, kLocalHost, kLocalPort);
            return orig_connect(fd, (const struct sockaddr *)&na, sizeof(na));
        }
    }
    return orig_connect(fd, addr, len);
}

// ── getaddrinfo 包装 ─────────────────────────────────────────────────
static int MRGetaddrinfo(const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res) {
    if (isGameloft(node)) {
        const char *port = service ? service : "443";
        MRLog("DNS %s:%s -> %s:%s", node, port, kLocalHost, port);
        return orig_getaddrinfo(kLocalHost, port, hints, res);
    }
    return orig_getaddrinfo(node, service, hints, res);
}

// ── gethostbyname 包装 ───────────────────────────────────────────────
static struct hostent *MRGethostbyname(const char *name) {
    if (isGameloft(name)) {
        MRLog("DNS(byname) %s -> %s", name, kLocalHost);
        return orig_gethostbyname(kLocalHost);
    }
    return orig_gethostbyname(name);
}

// ── 装载 ─────────────────────────────────────────────────────────────
void *MRFindSubstrateSymbol(const char *name) {
    const char *libs[] = {
        "Substrate", "CydiaSubstrate", "libsubstrate.dylib",
        "libhooker", "ElleKit", "ellekit",
        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/libellekit.dylib",
        NULL
    };
    for (int i = 0; libs[i]; i++) {
        void *h = dlopen(libs[i], RTLD_NOLOAD);
        if (!h) h = dlopen(libs[i], RTLD_LAZY);
        if (!h) continue;
        void *p = dlsym(h, name);
        if (p) {
            MRLog("从 %s 取到 %s = %p", libs[i], name, p);
            return p;
        }
    }
    // 有时注入库已把符号放进全局表
    void *p = dlsym(RTLD_DEFAULT, name);
    if (p) MRLog("从 RTLD_DEFAULT 取到 %s = %p", name, p);
    return p;
}

__attribute__((constructor))
static void MRNetInit(void) {
    logOpen();
    MRLog("========== MRNet 载入 ==========");

    NSBundle *b = [NSBundle mainBundle];
    MRLog("bundle = %s", [[b bundleIdentifier] UTF8String] ?: "?");
    MRLog("目标   = %s:%d  hookAnyPort=%d", kLocalHost, kLocalPort, kHookAnyPort);

    int hooked = 0;

    // ── 路线 1：MSHookFunction ──
    void *sym = MRFindSubstrateSymbol("MSHookFunction");
    if (sym) {
        MSHookFunction_t hookFn = (MSHookFunction_t)sym;
        void *c  = dlsym(RTLD_DEFAULT, "connect");
        void *ga = dlsym(RTLD_DEFAULT, "getaddrinfo");
        void *gh = dlsym(RTLD_DEFAULT, "gethostbyname");
        if (c)  { hookFn(c,  (void *)MRConnect,       (void **)&orig_connect);      hooked++; }
        if (ga) { hookFn(ga, (void *)MRGetaddrinfo,   (void **)&orig_getaddrinfo);  hooked++; }
        if (gh) { hookFn(gh, (void *)MRGethostbyname, (void **)&orig_gethostbyname); hooked++; }
        MRLog("路线1 MSHookFunction: %d/3", hooked);
    } else {
        MRLog("路线1 MSHookFunction 不可用，转用 fishhook");
    }

    // ── 路线 2：fishhook（无依赖，兜底）──
    if (hooked == 0) {
        struct mr_rebinding rb[] = {
            { "connect",       (void *)MRConnect,       (void **)&orig_connect },
            { "getaddrinfo",   (void *)MRGetaddrinfo,   (void **)&orig_getaddrinfo },
            { "gethostbyname", (void *)MRGethostbyname, (void **)&orig_gethostbyname },
        };
        int n = MRRebindSymbols(rb, sizeof(rb) / sizeof(rb[0]));
        MRLog("路线2 fishhook: 命中 %d 个指针", n);
        hooked = n;
    }

    if (hooked == 0) {
        MRLog("❌ 两条路线都失败，未拦截任何网络调用");
    } else {
        MRLog("✅ 已生效 %d 处", hooked);
    }

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        for (int i = 1; i <= 60; i++) {
            sleep(10);
            MRLog("HEARTBEAT #%d", i);
        }
    });
}
