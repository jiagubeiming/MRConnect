// MRState — Minion Rush 网络状态观测探针
//
// ═══════════════════════════════════════════════════════════════════
//  目标：找出游戏在哪里判定「离线」
// ═══════════════════════════════════════════════════════════════════
//
//  ✅ 只观测，不改变任何游戏行为 —— 这是和之前失败的 hook 的本质区别。
//
//  之前所有 hook 尝试（NSURLProtocol / 改 GOT / 改跳转）都失败了，
//  因为它们要「干预」。而这个探针只做三件事：
//
//    1. 记录网络层真实行为（socket / getsockname 对端）
//    2. 周期性快照主二进制 __DATA 段的全局变量，找出变化点
//    3. 记录已知关键对象的字段（若地址能定位到）
//
//  拿到变化点后，我们就能知道「哪一刻、哪个变量」把状态翻成了离线。
//
// ═══════════════════════════════════════════════════════════════════
//  为什么扫内存而不是 hook 函数
// ═══════════════════════════════════════════════════════════════════
//
//  游戏有 32 万个函数，我不知道哪个是判定函数。但状态判定必然落在一个
//  全局变量或对象字段上，且它一定会在「启动 → 离线」这段时间里发生变化。
//
//  所以：盯着所有全局变量，谁变了就记谁。变化点会自己浮现。
//
//  扫描范围：主二进制 __DATA / __DATA_CONST / __DATA_DIRTY / __BSS
//  （.data 段，不含代码，不会误扫到指令）
//
// ═══════════════════════════════════════════════════════════════════
//  日志位置
// ═══════════════════════════════════════════════════════════════════
//
//    ① 沙盒 Documents/MRState.log        （一定能写，用 Filza 可看）
//    ② /var/mobile/Documents/MRState.log （越狱环境）
//    ③ /var/mobile/Media/MRState.log
//    ④ /var/tmp/MRState.log
//
// ═══════════════════════════════════════════════════════════════════
//  卸载
// ═══════════════════════════════════════════════════════════════════
//
//    删除 MRState.dylib 与 MRState.plist
//    无根越狱在 /var/jb/Library/MobileSubstrate/DynamicLibraries/

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <sys/mman.h>
#import <sys/types.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <unistd.h>
#import <dlfcn.h>
#import <string.h>
#import <stdio.h>
#import <stdlib.h>
#import <stdarg.h>
#import <pthread.h>
#import <time.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>

// ════════════════════════════════════════════════���══════════════════
//  配置
// ═══════════════════════════════════════════════════════════════════

// 注意：越狱下第 0 个镜像是 systemhook-*.dylib，不能硬编码 0。
// 主程序改为按路径名在所有镜像中查找（见 MRSetupMainImage）。
#define MR_SCAN_DELAY         8.0        // 首次扫描前等待（让游戏先初始化）
#define MR_SCAN_INTERVAL      2.0        // 之后每 2 秒扫一次
#define MR_SCAN_COUNT         45         // 共扫 90 秒
#define MR_MAX_CHANGES        4000       // 最多记录多少条变化
#define MR_MAX_HOSTS          256        // 最多记录多少个连接目标

// ═══════════════════════════════════════════════════════════════════
//  日志
// ═══════════════════════════════════════════════════════════════════

static char gLogPath[512] = {0};
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long gSeq = 0;
static double gStartTime = 0;

static double MRNow(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void MROpenLog(void) {
    // 沙盒路径优先 —— 这个一定能写
    NSString *d = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                       NSUserDomainMask, YES) firstObject];
    if (d) {
        NSString *p = [d stringByAppendingPathComponent:@"MRState.log"];
        FILE *f = fopen([p UTF8String], "a");
        if (f) {
            fclose(f);
            strlcpy(gLogPath, [p UTF8String], sizeof(gLogPath));
            return;
        }
    }
    const char *cands[] = {
        "/var/mobile/Documents/MRState.log",
        "/var/mobile/Media/MRState.log",
        "/var/tmp/MRState.log",
        "/tmp/MRState.log",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        FILE *f = fopen(cands[i], "a");
        if (f) {
            fclose(f);
            strlcpy(gLogPath, cands[i], sizeof(gLogPath));
            return;
        }
    }
}

static void MRLog(const char *fmt, ...) {
    char msg[1600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    double t = MRNow() - gStartTime;

    pthread_mutex_lock(&gLock);
    if (gLogPath[0]) {
        FILE *f = fopen(gLogPath, "a");
        if (f) {
            fprintf(f, "%6.2fs %05lu %s\n", t, ++gSeq, msg);
            fclose(f);
        }
    }
    pthread_mutex_unlock(&gLock);
    NSLog(@"[MRSTATE] %s", msg);
}

// ═══════════════════════════════════════════════════════════════════
//  主程序镜像与内存区域
// ═══════════════════════════════════════════════════════════════════

static const struct mach_header_64 *gMainHdr = NULL;
static intptr_t gSlide = 0;

// 越狱环境（Dopamine/ellekit）下 _dyld_get_image_header(0) 往往不是主程序，
// 而是 systemhook-XXXX.dylib。必须按路径名在所有已加载镜像里查找 DespicableMe。
static BOOL MRLooksLikeMainExecutable(const char *name) {
    if (!name || !*name) return NO;
    if (strstr(name, "systemhook")) return NO;      // Dopamine 的劫持壳
    if (strstr(name, ".dylib")) return NO;          // 任何 dylib 都不算
    if (!strstr(name, "DespicableMe")) return NO;   // 主程序文件名
    return YES;
}

static BOOL MRSetupMainImage(void) {
    const struct mach_header *best = NULL;
    intptr_t bestSlide = 0;
    const char *bestName = NULL;

    uint32_t n = _dyld_image_count();
    MRLog("已加载镜像 %u 个，开始查找主程序", n);

    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!MRLooksLikeMainExecutable(nm)) continue;
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        // 主程序特征：数据段很大（几十 MB），用 __TEXT 大小粗筛
        best     = h;
        bestSlide = _dyld_get_image_vmaddr_slide(i);
        bestName = nm;
        MRLog("  命中 #%u %s", i, nm);
        break;
    }

    if (!best) {
        MRLog("❌ 未找到 DespicableMe 主程序镜像，列出全部：");
        for (uint32_t i = 0; i < n && i < 80; i++) {
            MRLog("    #%u %s", i, _dyld_get_image_name(i) ? _dyld_get_image_name(i) : "?");
        }
        return NO;
    }

    gMainHdr = (const struct mach_header_64 *)best;
    gSlide   = bestSlide;

    MRLog("主程序镜像 = %s", bestName);
    MRLog("  基址 = %p  slide = %p", (void *)best, (void *)gSlide);
    return YES;
}

// 从主程序 Mach-O 取出各 __DATA* 段的实际内存范围
typedef struct {
    char name[24];
    uintptr_t addr;      // 运行时实际地址（已加 slide）
    size_t    size;
} MRSeg;

static MRSeg gSegs[16];
static int  gSegCount = 0;

static void MRCollectDataSegments(void) {
    if (!gMainHdr) return;

    // 只有 __DATA 族段才含变量；__TEXT / __LINKEDIT 不含
    static const char *want[] = {
        "__DATA", "__DATA_CONST", "__DATA_DIRTY", "__AUTH", "__AUTH_CONST",
        "__BSS", "__COMMON", NULL
    };

    const uint8_t *q = (const uint8_t *)gMainHdr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < gMainHdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)q;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
            for (int k = 0; want[k]; k++) {
                if (strncmp(sc->segname, want[k], 16) == 0) {
                    if (gSegCount < 16) {
                        strlcpy(gSegs[gSegCount].name, sc->segname, sizeof(gSegs[0].name));
                        // __PAGEZERO 的 vmaddr=0，其余需要加 slide
                        gSegs[gSegCount].addr = (uintptr_t)sc->vmaddr + (uintptr_t)gSlide;
                        gSegs[gSegCount].size = (size_t)sc->vmsize;
                        MRLog("  段 %-16s addr=%p size=0x%zx",
                              sc->segname, (void *)gSegs[gSegCount].addr, gSegs[gSegCount].size);
                        gSegCount++;
                    }
                    break;
                }
            }
        }
        q += lc->cmdsize;
    }
    MRLog("共 %d 个数据段可扫描", gSegCount);
}

// ═══════════════════════════════════════════════════════════════════
//  网络目标记录（判断游戏实际连了哪里）
// ═══════════════════════════════════════════════════════════════════

static char gHosts[MR_MAX_HOSTS][96];
static int  gHostCount = 0;

static void MRNoteHost(const char *desc) {
    pthread_mutex_lock(&gLock);
    for (int i = 0; i < gHostCount; i++) {
        if (strcmp(gHosts[i], desc) == 0) {
            pthread_mutex_unlock(&gLock);
            return;
        }
    }
    BOOL isNew = (gHostCount < MR_MAX_HOSTS);
    if (isNew) {
        strlcpy(gHosts[gHostCount++], desc, sizeof(gHosts[0]));
    }
    pthread_mutex_unlock(&gLock);

    if (isNew) {
        MRLog("NET 新目标: %s", desc);
    }
}

// 扫描当前进程所有 TCP 连接（通过 getpeername 对已建立的 fd）
// 简化做法：不遍历 fd（成本高且易崩），改由 connect 记录 + 主动探测
static void MRDumpKnownHosts(void) {
    pthread_mutex_lock(&gLock);
    int n = gHostCount;
    char buf[MR_MAX_HOSTS][96];
    for (int i = 0; i < n && i < MR_MAX_HOSTS; i++) {
        strlcpy(buf[i], gHosts[i], sizeof(buf[0]));
    }
    pthread_mutex_unlock(&gLock);

    MRLog("── 累计网络目标 %d 个 ──", n);
    for (int i = 0; i < n; i++) {
        MRLog("   %s", buf[i]);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  ★ 核心：全局变量变化扫描
// ═══════════════════════════════════════════════════════════════════
//
//  把每个数据段的当前内容存一份快照，每 2 秒比对一次。
//  只记录「变化了」的 8 字节槽 —— 过滤掉指针抖动。
//
//  记录格式：
//     CHG 段名+0x偏移  旧值 -> 新值
//
//  然后用之前的分析能力反查这个偏移是什么。

typedef struct {
    uintptr_t addr;      // 绝对地址
    uint64_t  oldval;
    uint64_t  newval;
    int       segIdx;
    size_t    off;
    int       count;     // 变化次数
} MRChange;

static uint8_t *gSnap[16] = {0};
static MRChange gChanges[MR_MAX_CHANGES];
static int gChangeCount = 0;

static BOOL MRTakeSnapshot(void) {
    if (!gMainHdr || gSegCount == 0) return NO;

    for (int s = 0; s < gSegCount; s++) {
        if (!gSnap[s]) {
            gSnap[s] = (uint8_t *)calloc(1, gSegs[s].size);
            if (!gSnap[s]) return NO;
        }
    }
    return YES;
}

static void MRFirstSnapshot(void) {
    for (int s = 0; s < gSegCount; s++) {
        if (!gSnap[s]) continue;
        memcpy(gSnap[s], (const void *)gSegs[s].addr, gSegs[s].size);
    }
    MRLog("基线快照完成（%d 段）", gSegCount);
}

static void MRCompareSnapshot(void) {
    int found = 0;
    for (int s = 0; s < gSegCount; s++) {
        if (!gSnap[s]) continue;
        const uint8_t *cur = (const uint8_t *)gSegs[s].addr;
        uint8_t *old = gSnap[s];
        size_t n = gSegs[s].size;

        // 按 8 字节对齐比对
        for (size_t off = 0; off + 8 <= n; off += 8) {
            uint64_t o = *(const uint64_t *)(old + off);
            uint64_t c = *(const uint64_t *)(cur + off);
            if (o == c) continue;

            // 过滤：全是 0 或全是 0xff 的不算（未初始化 / 掩码）
            if ((o == 0 && c == 0) || (o == 0xffffffffffffffffULL && c == 0xffffffffffffffffULL))
                continue;

            // 已是已知变化点则累加计数
            BOOL known = NO;
            for (int k = 0; k < gChangeCount; k++) {
                if (gChanges[k].addr == (uintptr_t)(cur + off)) {
                    gChanges[k].newval = c;
                    gChanges[k].count++;
                    known = YES;
                    break;
                }
            }
            if (!known && gChangeCount < MR_MAX_CHANGES) {
                gChanges[gChangeCount].addr = (uintptr_t)(cur + off);
                gChanges[gChangeCount].oldval = o;
                gChanges[gChangeCount].newval = c;
                gChanges[gChangeCount].segIdx = s;
                gChanges[gChangeCount].off = off;
                gChanges[gChangeCount].count = 1;
                gChangeCount++;
                found++;

                // 只记录「小值」变化（0/1/2/3 这类状态值最可疑），
                // 指针大幅跳动噪音太大，只做计数
                if (c < 0x1000000ULL || o < 0x1000000ULL) {
                    MRLog("CHG %s+0x%-6zx  %llu -> %llu",
                          gSegs[s].name, off,
                          (unsigned long long)o, (unsigned long long)c);
                }
            }
        }
        // 更新快照
        memcpy(old, cur, n);
    }
    if (found > 0) {
        MRLog("本轮新增变化点 %d 个（累计 %d）", found, gChangeCount);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  可疑状态值专查
// ═══════════════════════════════════════════════════════════════════
//
//  「在线 / 离线」通常是 1 个字节或 1 个 int。
//  这里额外扫描所有值恰好是 0/1/2 的 int，并追踪它们何时变换。

typedef struct {
    uintptr_t addr;
    int32_t   last;
} MRSmallVal;

#define MR_MAX_SMALL 8000
static MRSmallVal gSmall[MR_MAX_SMALL];
static int gSmallCount = 0;

static void MRScanSmallValues(void) {
    // 只在 __DATA 主段找，范围可控
    if (gSegCount == 0) return;
    const uint8_t *base = (const uint8_t *)gSegs[0].addr;
    size_t n = gSegs[0].size;

    for (size_t off = 0; off + 4 <= n; off += 4) {
        int32_t v = *(const int32_t *)(base + off);
        if (v < 0 || v > 3) continue;

        BOOL found = NO;
        for (int k = 0; k < gSmallCount; k++) {
            if (gSmall[k].addr == (uintptr_t)(base + off)) {
                if (gSmall[k].last != v) {
                    // 状态值翻转 —— 高价值事件
                    if (gSmall[k].last == 1 && v == 0) {
                        MRLog("★★ 1->0  %s+0x%zx  （可能是「在线 -> 离线」）",
                              gSegs[0].name, off);
                    } else if (gSmall[k].last == 0 && v == 1) {
                        MRLog("★  0->1  %s+0x%zx", gSegs[0].name, off);
                    }
                    gSmall[k].last = v;
                }
                found = YES;
                break;
            }
        }
        if (!found && gSmallCount < MR_MAX_SMALL) {
            gSmall[gSmallCount].addr = (uintptr_t)(base + off);
            gSmall[gSmallCount].last = v;
            gSmallCount++;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  连接目标抓取（不 hook，用 dlsym 拿到 connect 自己包装）
// ═══════════════════════════════════════════════════════════════════
//
//  这里用 fishhook 式改 GOT 会失效（chained fixups），
//  但有一个不 hook 也能拿到目标的办法：定期枚举进程的 socket。
//
//  iOS 上可以用 proc_pidinfo 拿 fd 列表，再 getpeername。
//  但需要 <libproc.h>，且可能被沙盒拦。先用简单的：扫 /dev/fd。
//
static void MRDumpOpenSockets(void) {
    int seen = 0;
    for (int fd = 3; fd < 200; fd++) {
        struct sockaddr_in peer;
        socklen_t len = sizeof(peer);
        memset(&peer, 0, sizeof(peer));
        if (getpeername(fd, (struct sockaddr *)&peer, &len) != 0) continue;

        char ip[64] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        int port = ntohs(peer.sin_port);
        if (port == 0) continue;

        char desc[96];
        snprintf(desc, sizeof(desc), "%s:%d", ip, port);
        MRNoteHost(desc);
        seen++;
    }
    // 静默，有变化时由 MRNoteHost 打日志
    (void)seen;
}

// ═══════════════════════════════════════════════════════════════════
//  已知关键对象巡检（来自之前静态分析的结论）
// ═══════════════════════════════════════════════════════════════════
//
//  这些地址是主程序里的全局指针槽，运行时填值。
//  它们不是「判定点」，但能反映系统处于什么阶段。
//
static void MRInspectKnownGlobals(void) {
    if (!gMainHdr || gSlide == 0) {
        // slide 可能是 0（极少见），仍尝试
    }
    struct { const char *name; uintptr_t va; } g[] = {
        { "主管理器 MGR",        0x103f38ed0 },
        { "房间管理器",          0x103f39480 },
        { "房间任务管理器",      0x103f39588 },
        { "房间条目容器",        0x103f39580 },
        { "结果对象",            0x103f395d0 },
        { "Menu_Lair 服务槽",    0x104084da8 },
        { "Menu_Result 槽",      0x104086828 },
        { "Menu_MyCareer 槽",    0x104089220 },
        { "Menu_ActionPhase 槽", 0x104082b48 },
        { NULL, 0 }
    };
    for (int i = 0; g[i].name; i++) {
        uintptr_t addr = g[i].va + (uintptr_t)gSlide;
        // 简单可读性检查
        uint64_t v = 0;
        // 用 vm_read_overwrite 判断可读
        vm_size_t outSize = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                             8, (vm_address_t)&v, &outSize);
        if (kr == KERN_SUCCESS && outSize == 8) {
            MRLog("GLB %-20s @%p = 0x%llx", g[i].name, (void *)addr,
                  (unsigned long long)v);
        } else {
            MRLog("GLB %-20s @%p 不可读 (kr=%d)", g[i].name, (void *)addr, (int)kr);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  主循环
// ═══════════════════════════════════════════════════════════════════

static void MRSamplerThread(void) {
    // 等待游戏完成早期初始化
    sleep((unsigned)MR_SCAN_DELAY);

    if (!gMainHdr) {
        MRLog("主程序镜像未就绪，放弃");
        return;
    }

    MRLog("════════ 开始扫描 ════════");
    MRInspectKnownGlobals();

    if (!MRTakeSnapshot()) {
        MRLog("内存分配失败，放弃");
        return;
    }
    MRFirstSnapshot();

    for (int round = 1; round <= MR_SCAN_COUNT; round++) {
        sleep((unsigned)MR_SCAN_INTERVAL);

        MRCompareSnapshot();
        MRScanSmallValues();
        MRDumpOpenSockets();

        if (round % 10 == 0) {
            MRInspectKnownGlobals();
            MRLog("── 第 %d 轮完成，变化点 %d ──", round, gChangeCount);
        }
    }

    MRLog("════════ 扫描结束 ════════");
    MRInspectKnownGlobals();
    MRDumpKnownHosts();

    // 输出所有已记录的变化点（按变化次数排序）
    MRLog("全部变化点（累计 %d）：", gChangeCount);
    // 冒泡取前 60 个高价值（变化次数多的 + 小值的）
    int shown = 0;
    for (int pass = 0; pass < 60 && shown < 60; pass++) {
        int best = -1, bestCnt = 0;
        for (int k = 0; k < gChangeCount; k++) {
            if (gChanges[k].count > bestCnt && gChanges[k].count < 100000) {
                BOOL done = NO;
                for (int p = 0; p < shown; p++) { /* 已打印的不重复 */ }
                if (!done) { best = k; bestCnt = gChanges[k].count; }
            }
        }
        if (best < 0) break;
        MRLog("  %s+0x%-6zx  %llu->%llu  次数=%d",
              gSegs[gChanges[best].segIdx].name, gChanges[best].off,
              (unsigned long long)gChanges[best].oldval,
              (unsigned long long)gChanges[best].newval,
              gChanges[best].count);
        gChanges[best].count = 100000;   // 标记已打印
        shown++;
    }
}

// ═══════════════════════════════════════════════════════════════════
//  入口
// ═══════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void MRStateInit(void) {
    gStartTime = MRNow();
    MROpenLog();

    MRLog("════════ MRState 载入 ════════");
    MRLog("bundle = %s", [[[NSBundle mainBundle] bundleIdentifier] UTF8String]);
    MRLog("日志   = %s", gLogPath);
    MRLog("系统   = %s", [[[NSProcessInfo processInfo] operatingSystemVersionString] UTF8String]);

    if (!MRSetupMainImage()) {
        MRLog("❌ 主程序镜像解析失败");
        return;
    }
    MRCollectDataSegments();

    if (gSegCount == 0) {
        MRLog("❌ 未找到可扫描的数据段");
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        MRSamplerThread();
    });
}
