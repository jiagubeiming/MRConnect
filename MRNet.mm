// MRNet.mm —— 进程内网络拦截（安卓 libmroffline.so offline_hook_connect 的 iOS 同构版）
//
// 思路：
//   游戏主程序的 libcurl 是静态链接的，但 connect/getaddrinfo/send/recv 都是
//   动态导入 libSystem 的。用 MSHookFunction 挂这几个函数，就能在进程内
//   把「到 gameloft 的连接」改写成「到本地假服务器」，或者干脆自己应答。
//
// 本版只做第一件事：**把连接改向本机 443**，并对所有 gameloft 域名的
// getaddrinfo 返回 127.0.0.1。TLS 仍由本地 Python 服务器持有真证书完成。
//
// 不改变游戏逻辑，只改变网络目的地。

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <dlfcn.h>
#import <string.h>
#import <stdarg.h>
#import <stdio.h>
#import <unistd.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <mach/mach.h>
#import <pthread.h>

// ── 配置 ─────────────────────────────────────────────────────────────
// 本地假服务器地址。改这里就能换目标。
static const char *kLocalHost = "192.168.123.83";
static const int   kLocalPort = 443;

// 需要劫持的域名后缀
static const char *kDomains[] = {
    "gameloft.com", "gameloft.net", "gameloft.org", NULL
};

// ── 日志 ─────────────────────────────────────────────────────────────
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;
static char gLogPath[512] = {0};
static int  gSeenHosts[256] = {0};
static int  gSeenCount = 0;

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
    // 沙盒兜底
    NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (d) {
        snprintf(gLogPath, sizeof(gLogPath), "%s/MRNet.log", [d UTF8String]);
    }
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
        fprintf(f, "%07lu %s\n", (unsigned long)(time(NULL) % 10000000), buf);
        fclose(f);
    }
    pthread_mutex_unlock(&gLock);
}

static int markSeen(const char *host) {
    pthread_mutex_lock(&gLock);
    int seen = 0;
    for (int i = 0; i < gSeenCount; i++) {
        // 简易去重：按指针内容比较不方便，直接每次打印（数量不大）
        seen = 0;
    }
    (void)host;
    pthread_mutex_unlock(&gLock);
    return seen;
}

// ── 域名判定 ─────────────────────────────────────────────────────────
static int isGameloft(const char *host) {
    if (!host || !*host) return 0;
    if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0) return 0;
    for (int i = 0; kDomains[i]; i++) {
        size_t hl = strlen(host), dl = strlen(kDomains[i]);
        if (hl >= dl && strcasecmp(host + hl - dl, kDomains[i]) == 0) return 1;
    }
    return 0;
}

// ── 被挂载的原函数 ───────────────────────────────────────────────────
static int  (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int  (*orig_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *, struct addrinfo **);
static struct hostent *(*orig_gethostbyname)(const char *);

// ── connect 包装 ─────────────────────────────────────────────────────
static int MRConnect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
            char ip[64];
            inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
            int port = ntohs(in->sin_port);

            // 不是本地服务器、且目标是公网 → 改向
            if (port == 443 && strcmp(ip, kLocalHost) != 0 && strcmp(ip, "127.0.0.1") != 0) {
                struct sockaddr_in na;
                memset(&na, 0, sizeof(na));
                na.sin_family = AF_INET;
                na.sin_port = htons(kLocalPort);
                inet_pton(AF_INET, kLocalHost, &na.sin_addr);
                MRLog("REDIR connect %s:443 -> %s:%d", ip, kLocalHost, kLocalPort);
                return orig_connect(fd, (const struct sockaddr *)&na, sizeof(na));
            }
        } else {
            const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
            int port = ntohs(in6->sin6_port);
            char ip[64] = "::?";
            inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
            if (port == 443 && strcmp(ip, "::1") != 0) {
                struct sockaddr_in na;
                memset(&na, 0, sizeof(na));
                na.sin_family = AF_INET;
                na.sin_port = htons(kLocalPort);
                inet_pton(AF_INET, kLocalHost, &na.sin_addr);
                MRLog("REDIR6 connect %s:443 -> %s:%d", ip, kLocalHost, kLocalPort);
                return orig_connect(fd, (const struct sockaddr *)&na, sizeof(na));
            }
        }
    }
    return orig_connect(fd, addr, len);
}

// ── getaddrinfo 包装 ─────────────────────────────────────────────────
static int MRGetaddrinfo(const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res) {
    if (isGameloft(node)) {
        MRLog("DNS %s -> %s", node, kLocalHost);
        const char *port = service ? service : "443";
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
__attribute__((constructor))
static void MRNetInit(void) {
    logOpen();

    NSBundle *b = [NSBundle mainBundle];
    MRLog("========== MRNet 载入 ==========");
    MRLog("bundle = %s", [[b bundleIdentifier] UTF8String] ?: "?");
    MRLog("目标   = %s:%d", kLocalHost, kLocalPort);
    MRLog("sysver = %s", [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String] ?: "?");

    void *c  = dlsym(RTLD_DEFAULT, "connect");
    void *ga = dlsym(RTLD_DEFAULT, "getaddrinfo");
    void *gh = dlsym(RTLD_DEFAULT, "gethostbyname");

    MRLog("dlsym connect=%p getaddrinfo=%p gethostbyname=%p", c, ga, gh);

    int n = 0;
    if (c)  { MSHookFunction(c,  (void *)MRConnect,      (void **)&orig_connect);      n++; }
    if (ga) { MSHookFunction(ga, (void *)MRGetaddrinfo,  (void **)&orig_getaddrinfo);  n++; }
    if (gh) { MSHookFunction(gh, (void *)MRGethostbyname, (void **)&orig_gethostbyname); n++; }

    MRLog("已挂载 %d/3 个函数", n);

    // 心跳，每 10 秒一次，共 60 次（10 分钟）
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        for (int i = 1; i <= 60; i++) {
            sleep(10);
            MRLog("HEARTBEAT #%d", i);
        }
    });
}
