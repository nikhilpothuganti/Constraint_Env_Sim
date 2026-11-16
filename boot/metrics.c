/*
 * metrics.c - see metrics.h.
 */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#include <stdlib.h>
#include <string.h>

#include "metrics.h"
#include "timing.h"

#include <stdio.h>

uint64_t metrics_wait_cycles;

/* ------------------------------------------------------------- heap */
/* Each block carries an 8-byte header with its size (8 keeps the payload
 * 8-byte aligned like malloc's). */
#define HDR 8
static struct heap_stats hs;
static int cur_phase = -1, peak_phase = -1;   /* PQC op running at peak */
static size_t phase_base, peak_base;          /* heap in use when it began */

#ifdef METRICS_HEAPDUMP
/* Debug aid (make HEAPDUMP=1): table of live blocks, dumped by size when
 * ML-DSA signing starts (the heap peak), to see what holds memory. */
#define LIVE_MAX 768
static struct { void *p; size_t n; } live[LIVE_MAX];
static void live_add(void *p, size_t n)
{
    for (int i = 0; i < LIVE_MAX; i++)
        if (!live[i].p) { live[i].p = p; live[i].n = n; return; }
}
static void live_del(void *p)
{
    for (int i = 0; i < LIVE_MAX; i++)
        if (live[i].p == p) { live[i].p = NULL; return; }
}
#include <wolfssl/internal.h>
static void live_dump(void)
{
    size_t tot = 0; int cnt = 0;
    printf("[heapdump] sizeof WOLFSSL %u, WOLFSSL_CTX %u, dilithium_key %u, MlKemKey %u, "
           "DecodedCert %u, WOLFSSL_X509 %u, Signer %u, Arrays %u\n",
           (unsigned)sizeof(WOLFSSL), (unsigned)sizeof(WOLFSSL_CTX),
           (unsigned)sizeof(dilithium_key), (unsigned)sizeof(MlKemKey),
           (unsigned)sizeof(DecodedCert), (unsigned)sizeof(WOLFSSL_X509),
           (unsigned)sizeof(Signer), (unsigned)sizeof(Arrays));
    printf("[heapdump] live blocks >= 256 B at ML-DSA sign start:\n");
    for (;;) {                       /* selection by size, largest first */
        int best = -1;
        for (int i = 0; i < LIVE_MAX; i++)
            if (live[i].p && (int)live[i].n > 0 && (best < 0 || live[i].n > live[best].n))
                best = i;
        if (best < 0) break;
        if (live[best].n >= 256)
            printf("[heapdump]   %6lu B\n", (unsigned long)live[best].n);
        tot += live[best].n; cnt++;
        live[best].n = -live[best].n;   /* mark printed */
    }
    for (int i = 0; i < LIVE_MAX; i++)
        if (live[i].p) live[i].n = -live[i].n;
    printf("[heapdump] %d blocks, %lu B\n", cnt, (unsigned long)tot);
}
#else
#define live_add(p, n) do { } while (0)
#define live_del(p)    do { } while (0)
#endif

static void *m_malloc(size_t n)
{
    unsigned char *p = malloc(n + HDR);
    if (!p)
        return NULL;
    *(size_t *)p = n;
    live_add(p + HDR, n);
    hs.cur += n;
    hs.allocs++;
    if (hs.cur > hs.peak) {
        hs.peak = hs.cur;
        peak_phase = cur_phase;
        peak_base = cur_phase < 0 ? 0 : phase_base;
    }
    return p + HDR;
}

static void m_free(void *ptr)
{
    if (!ptr)
        return;
    unsigned char *p = (unsigned char *)ptr - HDR;
    hs.cur -= *(size_t *)p;
    hs.frees++;
    live_del(ptr);
    free(p);
}

static void *m_realloc(void *ptr, size_t n)
{
    if (!ptr)
        return m_malloc(n);
    unsigned char *p = (unsigned char *)ptr - HDR;
    size_t old = *(size_t *)p;
    unsigned char *q = realloc(p, n + HDR);
    if (!q)
        return NULL;
    *(size_t *)q = n;
    live_del(ptr);
    live_add(q + HDR, n);
    hs.cur = hs.cur - old + n;
    if (hs.cur > hs.peak) {
        hs.peak = hs.cur;
        peak_phase = cur_phase;
    }
    return q + HDR;
}

const struct heap_stats *metrics_heap(void) { return &hs; }
void metrics_heap_reset_peak(void) { hs.peak = hs.cur; }

/* ------------------------------------------------------------ stack */
extern char __stack_start[];        /* linker.ld: lowest stack address */
#define PAINT 0x5AC4D1E5u

void metrics_init(void)
{
    /* Paint from the bottom of the stack to just below the current frame. */
    uint32_t *p = (uint32_t *)__stack_start;
    uint32_t *sp = (uint32_t *)__builtin_frame_address(0) - 64;
    while (p < sp)
        *p++ = PAINT;
    wolfSSL_SetAllocators(m_malloc, m_free, m_realloc);
}

size_t metrics_stack_peak(void)
{
    extern char __stack_end[];
    uint32_t *p = (uint32_t *)__stack_start;
    while (p < (uint32_t *)__stack_end && *p == PAINT)
        p++;
    return (size_t)(__stack_end - (char *)p);
}

/* ------------------------------------------------ PQC phase timing */
struct phase metrics_phase[PH_COUNT];

extern uint32_t metrics_keccak_calls;
void metrics_phase_reset(void)
{
    memset(metrics_phase, 0, sizeof metrics_phase);
    metrics_keccak_calls = 0;
}

void metrics_phase_print(void)
{
    static const char *const name[PH_COUNT] = {
        "ML-DSA-44 sign", "ML-DSA-44 verify", "ML-KEM-512 keygen", "ML-KEM-512 decaps" };
    for (int i = 0; i < PH_COUNT; i++)
        printf("    %-24s %10lu cycles in %lu call(s)\n", name[i],
               (unsigned long)metrics_phase[i].cycles, (unsigned long)metrics_phase[i].calls);
    printf("    %-24s %10lu\n", "Keccak-f[1600] calls", (unsigned long)metrics_keccak_calls);
    printf("    heap peak %lu B reached %s%s, %lu B live before it\n",
           (unsigned long)hs.peak, peak_phase < 0 ? "outside PQC ops" : "in ",
           peak_phase < 0 ? "" : name[peak_phase], (unsigned long)peak_base);
}

#define TIMED(ph, call)                                         \
    do {                                                        \
        uint64_t t0_ = cycles_now();                            \
        phase_base = hs.cur;                                    \
        cur_phase = (ph);                                       \
        int r_ = (call);                                        \
        cur_phase = -1;                                         \
        metrics_phase[ph].cycles += cycles_now() - t0_;         \
        metrics_phase[ph].calls++;                              \
        return r_;                                              \
    } while (0)

int __real_wc_dilithium_sign_ctx_msg(const byte *ctx, byte ctxLen, const byte *msg,
    word32 msgLen, byte *sig, word32 *sigLen, dilithium_key *key, WC_RNG *rng);
int __wrap_wc_dilithium_sign_ctx_msg(const byte *ctx, byte ctxLen, const byte *msg,
    word32 msgLen, byte *sig, word32 *sigLen, dilithium_key *key, WC_RNG *rng);
int __wrap_wc_dilithium_sign_ctx_msg(const byte *ctx, byte ctxLen, const byte *msg,
    word32 msgLen, byte *sig, word32 *sigLen, dilithium_key *key, WC_RNG *rng)
{
#ifdef METRICS_HEAPDUMP
    live_dump();
#endif
    TIMED(PH_MLDSA_SIGN, __real_wc_dilithium_sign_ctx_msg(ctx, ctxLen, msg, msgLen,
                                                           sig, sigLen, key, rng));
}

int __real_wc_dilithium_verify_ctx_msg(const byte *sig, word32 sigLen, const byte *ctx,
    word32 ctxLen, const byte *msg, word32 msgLen, int *res, dilithium_key *key);
int __wrap_wc_dilithium_verify_ctx_msg(const byte *sig, word32 sigLen, const byte *ctx,
    word32 ctxLen, const byte *msg, word32 msgLen, int *res, dilithium_key *key);
int __wrap_wc_dilithium_verify_ctx_msg(const byte *sig, word32 sigLen, const byte *ctx,
    word32 ctxLen, const byte *msg, word32 msgLen, int *res, dilithium_key *key)
{
    TIMED(PH_MLDSA_VERIFY, __real_wc_dilithium_verify_ctx_msg(sig, sigLen, ctx, ctxLen,
                                                               msg, msgLen, res, key));
}

int __real_wc_MlKemKey_MakeKey(MlKemKey *key, WC_RNG *rng);
int __wrap_wc_MlKemKey_MakeKey(MlKemKey *key, WC_RNG *rng);
int __wrap_wc_MlKemKey_MakeKey(MlKemKey *key, WC_RNG *rng)
{
    TIMED(PH_MLKEM_KEYGEN, __real_wc_MlKemKey_MakeKey(key, rng));
}

int __real_wc_MlKemKey_Decapsulate(MlKemKey *key, unsigned char *ss,
    const unsigned char *ct, word32 len);
int __wrap_wc_MlKemKey_Decapsulate(MlKemKey *key, unsigned char *ss,
    const unsigned char *ct, word32 len);
int __wrap_wc_MlKemKey_Decapsulate(MlKemKey *key, unsigned char *ss,
    const unsigned char *ct, word32 len)
{
    TIMED(PH_MLKEM_DECAPS, __real_wc_MlKemKey_Decapsulate(key, ss, ct, len));
}

int __real_wc_dilithium_verify_msg(const byte *sig, word32 sigLen, const byte *msg,
    word32 msgLen, int *res, dilithium_key *key);
int __wrap_wc_dilithium_verify_msg(const byte *sig, word32 sigLen, const byte *msg,
    word32 msgLen, int *res, dilithium_key *key);
int __wrap_wc_dilithium_verify_msg(const byte *sig, word32 sigLen, const byte *msg,
    word32 msgLen, int *res, dilithium_key *key)
{
    TIMED(PH_MLDSA_VERIFY, __real_wc_dilithium_verify_msg(sig, sigLen, msg, msgLen, res, key));
}

/* Keccak-f[1600] permutations (sha3.c -> keccak_rv32.c is a cross-file call). */
uint32_t metrics_keccak_calls;
void __real_BlockSha3(word64 *s);
void __wrap_BlockSha3(word64 *s);
void __wrap_BlockSha3(word64 *s)
{
    metrics_keccak_calls++;
    __real_BlockSha3(s);
}
