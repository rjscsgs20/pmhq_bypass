/* pmhq 8.1.1 免授权补丁 (LD_PRELOAD)
 * 各补丁点带字节校验,不匹配则跳过。仅适配 8.1.1。
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#define GATE_MISSING_OFF 0x19e3f5UL  /* je  -> 空 token 退出 */
#define GATE_TOKEN_OFF   0x19e441UL  /* je  -> auth_token is empty 退出 */
#define GATE_401_OFF     0x19e8c5UL  /* je  -> 401 退出 */
#define STATUS_OFF       0x19e880UL  /* movzwl 取 HTTP 状态 */
#define GATE_RESULT_OFF  0x19eb4bUL  /* jne -> 结果校验失败退出 */
#define TRIG_BIND_OFF    0x17f81cUL  /* call bind_uin 上报 */
#define TRIG_SETUIN_OFF  0x17f943UL  /* call set_uin 上报 */
#define TRIG_PREFLIGHT_OFF 0x19e745UL /* je -> 预检本地短路 */

static const unsigned char EXP_MISSING[] = {0x0f,0x84,0x2b,0x01,0x00,0x00};
static const unsigned char EXP_TOKEN[]   = {0x0f,0x84,0x1e,0x01,0x00,0x00};
static const unsigned char EXP_401[]     = {0x0f,0x84,0x69,0x4f,0x00,0x00};
static const unsigned char EXP_STATUS[]  = {0x44,0x0f,0xb7,0xb6,0x08,0x01,0x00,0x00};
static const unsigned char EXP_RESULT[]  = {0x0f,0x85,0x93,0x00,0x00,0x00};
static const unsigned char EXP_BIND[]    = {0xe8,0x62,0x80,0xff,0xff};
static const unsigned char EXP_SETUIN[]  = {0xe8,0x71,0x62,0xff,0xff};
static const unsigned char EXP_PREFLIGHT[]={0x0f,0x84,0x29,0x02,0x00,0x00};
/* jmp 0x19e974(本地短路) + nop */
static const unsigned char REPL_PREFLIGHT[]={0xe9,0x2a,0x02,0x00,0x00,0x90};

static unsigned long g_base;
static int armed;

static unsigned long find_base(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long b = 0;
    if (f) {
        while (fgets(line, sizeof(line), f))
            if (strstr(line, "/opt/pmhq")) { sscanf(line, "%lx", &b); break; }
        fclose(f);
    }
    return b;
}

/* 字节不匹配则跳过。内部 mprotect 走钩子短路分支,不会递归 */
static void patch_point(unsigned long off, const unsigned char *expect,
                        const unsigned char *repl, int n) {
    unsigned char *p = (unsigned char *)(g_base + off);
    unsigned long page = (g_base + off) & ~0xFFFUL;
    if (memcmp(p, expect, (size_t)n) != 0) return;
    if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC)) return;
    memcpy(p, repl, (size_t)n);
    mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
}

int mprotect(void *addr, size_t len, int prot) {
    static int (*real)(void *, size_t, int);
    if (!real) real = dlsym(RTLD_NEXT, "mprotect");
    int r = real(addr, len, prot);
    if (armed || (prot & PROT_WRITE) || !(prot & PROT_EXEC) || len <= 0x200000)
        return r;
    if (!g_base && !(g_base = find_base()))
        return r;
    static const unsigned char nop5[5] = {0x90,0x90,0x90,0x90,0x90};
    static const unsigned char nop6[6] = {0x90,0x90,0x90,0x90,0x90,0x90};
    /* mov $200, r14d; nops —— 状态强制 200 */
    static const unsigned char st200[8] = {0x41,0xbe,0xc8,0x00,0x00,0x00,0x90,0x90};
    /* 先改 gate 再动其它 */
    patch_point(GATE_MISSING_OFF, EXP_MISSING, nop6, 6);
    patch_point(GATE_TOKEN_OFF,   EXP_TOKEN,   nop6, 6);
    patch_point(GATE_401_OFF,     EXP_401,     nop6, 6);
    patch_point(STATUS_OFF,       EXP_STATUS,  st200, 8);
    patch_point(GATE_RESULT_OFF,  EXP_RESULT,  nop6, 6);
    /* 上报调用点,调用方不使用返回值 */
    patch_point(TRIG_BIND_OFF,   EXP_BIND,   nop5, 5);
    patch_point(TRIG_SETUIN_OFF, EXP_SETUIN, nop5, 5);
    /* 预检恒走本地短路,不构造请求 */
    patch_point(TRIG_PREFLIGHT_OFF, EXP_PREFLIGHT, REPL_PREFLIGHT, 6);
    armed = 1;
    return r;
}
