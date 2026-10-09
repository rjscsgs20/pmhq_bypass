/* pmhq 9.0.3 免授权补丁 (LD_PRELOAD)
 * token 读取清零 -> 授权请求不构造;gate 全放行,照常起 QQ。仅适配 9.0.3。
 * 9 处补丁全有或全无:全表字节校验通过才打。
 */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TOKPTR_OFF       0x1bb68cUL  /* mov 0x710(%rsp),%r15 ; token ptr */
#define TOKLEN_OFF       0x1bb694UL  /* mov 0x718(%rsp),%r12 ; token len */
#define GATE_EMPTY_OFF   0x1bb6b1UL  /* je  -> 空 token 跳过 SDK 初始化  */
#define GATE_SDK_OFF     0x1bb705UL  /* jne -> SDK 报错退出               */
#define GATE_VERDICT_OFF 0x1bb723UL  /* jne -> 判定失败退出               */
#define FLAG_TOKEN_OFF   0x1bba6cUL  /* test rbx,rbx 是否"配过 token"   */
#define API_QR_OFF       0x1d3f56UL  /* je  -> /get_login_qrcode 503     */
#define API_SEND_OFF     0x1d7039UL  /* je  -> /send 503                 */
#define API_WS_OFF       0x1d7aacUL  /* je  -> /ws 503                   */

static const unsigned char EXP_TOKPTR[]  = {0x4c,0x8b,0xbc,0x24,0x10,0x07,0x00,0x00};
static const unsigned char REPL_TOKPTR[] = {0x41,0xbf,0x00,0x00,0x00,0x00,0x90,0x90}; /* mov $0,%r15d */
static const unsigned char EXP_TOKLEN[]  = {0x4c,0x8b,0xa4,0x24,0x18,0x07,0x00,0x00};
static const unsigned char REPL_TOKLEN[] = {0x41,0xbc,0x00,0x00,0x00,0x00,0x90,0x90}; /* mov $0,%r12d */
static const unsigned char EXP_G1[]      = {0x0f,0x84,0x81,0x00,0x00,0x00};
static const unsigned char EXP_G2[]      = {0x0f,0x85,0x07,0x02,0x00,0x00};
static const unsigned char EXP_G3[]      = {0x0f,0x85,0xef,0x03,0x00,0x00};
static const unsigned char EXP_FLAG[]    = {0x48,0x85,0xdb};
static const unsigned char REPL_FLAG[]   = {0x48,0xff,0xc3}; /* inc rbx */
static const unsigned char EXP_QR[]      = {0x0f,0x84,0x0b,0x02,0x00,0x00};
static const unsigned char EXP_SEND[]    = {0x0f,0x84,0xb3,0x00,0x00,0x00};
static const unsigned char EXP_WS[]      = {0x0f,0x84,0x48,0x02,0x00,0x00};
static const unsigned char NOP6[]        = {0x90,0x90,0x90,0x90,0x90,0x90};

struct patch {
    const char *what;
    unsigned long off;
    const unsigned char *expect;
    const unsigned char *repl;
    unsigned n;
};

static const struct patch PATCHES[] = {
    {"token-read-ptr",       TOKPTR_OFF,       EXP_TOKPTR, REPL_TOKPTR, 8},
    {"token-read-len",       TOKLEN_OFF,       EXP_TOKLEN, REPL_TOKLEN, 8},
    {"gate-empty-token",     GATE_EMPTY_OFF,   EXP_G1,     NOP6,        6},
    {"gate-sdk-empty",       GATE_SDK_OFF,     EXP_G2,     NOP6,        6},
    {"gate-verdict",         GATE_VERDICT_OFF, EXP_G3,     NOP6,        6},
    {"flag-token",           FLAG_TOKEN_OFF,   EXP_FLAG,   REPL_FLAG,   3},
    {"api-get_login_qrcode", API_QR_OFF,       EXP_QR,     NOP6,        6},
    {"api-send",             API_SEND_OFF,     EXP_SEND,   NOP6,        6},
    {"api-ws",               API_WS_OFF,       EXP_WS,     NOP6,        6},
};
#define NPATCHES (sizeof(PATCHES) / sizeof(PATCHES[0]))

static int self_exe(char *out, size_t n) {
    ssize_t r = readlink("/proc/self/exe", out, n - 1);
    if (r <= 0) { out[0] = 0; return 0; }
    out[r] = 0;
    return 1;
}

/* base = 可执行文件映射中 p_offset==0 段的起始地址 */
static unsigned long find_exe_base(void) {
    char exe[1024], buf[262144];
    if (!self_exe(exe, sizeof(exe))) return 0;
    size_t exl = strlen(exe);
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    unsigned long best = ~0UL;
    char *p = buf;
    while (p && *p) {
        char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > exl + 1 && !memcmp(p + len - exl, exe, exl)) {
            unsigned long start = strtoul(p, NULL, 16);
            long off = -1;
            int i = 0;
            for (char *q = p; *q; q++) {
                if (*q == ' ' && ++i == 3) { off = strtol(q + 1, NULL, 16); break; }
            }
            if (off == 0 && start < best) best = start;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return best == ~0UL ? 0 : best;
}

/* 全有或全无:全表匹配才打 */
static int patches_match(unsigned long base) {
    unsigned i;
    for (i = 0; i < NPATCHES; i++) {
        const unsigned char *at = (const unsigned char *)(base + PATCHES[i].off);
        if (memcmp(at, PATCHES[i].expect, PATCHES[i].n) != 0) return 0;
    }
    return 1;
}

static void patches_apply(unsigned long base) {
    unsigned i;
    for (i = 0; i < NPATCHES; i++) {
        unsigned char *at = (unsigned char *)(base + PATCHES[i].off);
        unsigned long page = (unsigned long)at & ~0xFFFUL;
        size_t span = ((unsigned long)at + PATCHES[i].n - page + 0xFFFUL) & ~0xFFFUL;
        if (mprotect((void *)page, span, PROT_READ | PROT_WRITE | PROT_EXEC)) continue;
        memcpy(at, PATCHES[i].repl, PATCHES[i].n);
        mprotect((void *)page, span, PROT_READ | PROT_EXEC);
    }
}

__attribute__((constructor)) static void bypass_init(void) {
    char exe[1024];
    char *slash;
    unsigned long base;

    if (!self_exe(exe, sizeof(exe))) return;
    slash = strrchr(exe, '/');
    if (!slash || strncmp(slash + 1, "pmhq", 4)) return;  /* 其它进程惰性 */
    base = find_exe_base();
    if (base && patches_match(base)) patches_apply(base);
}
