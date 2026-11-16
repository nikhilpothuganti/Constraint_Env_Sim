/*
 * bench.c - per-primitive cycle counts on the device (make BENCH=1).
 *
 * Times the building blocks of the handshake in isolation with the RISC-V
 * cycle counter: Keccak-f[1600], ML-KEM-512, ML-DSA-44, AES-128-GCM,
 * SHA-256. ML-DSA signing uses rejection sampling, so it is run with
 * several fixed seeds (deterministic, repeatable) and min/avg/max reported.
 */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include <stdio.h>
#include <string.h>

#include "bench.h"
#include "timing.h"

void BlockSha3(word64 *s);      /* wolfCrypt internal (WOLFSSL_LOCAL) */

#define SIGN_SEEDS 8

static void row(const char *what, uint64_t c)
{
    printf("  %-34s %10lu cycles\n", what, (unsigned long)c);
}

static int bench_keccak(void)
{
    static word64 st[25];
    const int n = 64;

    /* Known answers: Keccak-f[1600] of the zero state (first lane), and
     * SHA3-256("abc") (FIPS 202 example). */
    BlockSha3(st);
    if (st[0] != W64LIT(0xF1258F7940E1DDE7)) {
        printf("Keccak KAT FAILED\n");
        return -1;
    }
    {
        static const byte abc_sha3[32] = {
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17,
            0x2d, 0x6b, 0xd3, 0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d,
            0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32 };
        byte h[32];
        wc_Sha3 sha3;
        wc_InitSha3_256(&sha3, NULL, INVALID_DEVID);
        wc_Sha3_256_Update(&sha3, (const byte *)"abc", 3);
        wc_Sha3_256_Final(&sha3, h);
        if (memcmp(h, abc_sha3, 32)) {
            printf("SHA3-256 KAT FAILED\n");
            return -1;
        }
        printf("  Keccak/SHA3-256 known-answer tests OK\n");
    }
    uint64_t t = cycles_now();
    for (int i = 0; i < n; i++)
        BlockSha3(st);
    row("Keccak-f[1600] permutation", (cycles_now() - t) / n);
    return 0;
}

static int bench_sym(void)
{
    static byte buf[1024], out[1024];
    byte digest[32], key[16] = {1}, iv[12] = {2}, tag[16];
    wc_Sha256 sha;
    Aes aes;

    /* Known answers (FIPS 180-2): "abc" and the 2-block 448-bit message. */
    {
        static const char *msg[2] = { "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" };
        static const byte exp[2][4] = { { 0xba, 0x78, 0x16, 0xbf }, { 0x24, 0x8d, 0x6a, 0x61 } };
        static const byte exp_tail[2][4] = { { 0xf2, 0x00, 0x15, 0xad }, { 0x19, 0xdb, 0x06, 0xc1 } };
        for (int i = 0; i < 2; i++) {
            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, (const byte *)msg[i], (word32)strlen(msg[i]));
            wc_Sha256Final(&sha, digest);
            if (memcmp(digest, exp[i], 4) || memcmp(digest + 28, exp_tail[i], 4)) {
                printf("SHA-256 KAT %d FAILED\n", i);
                return -1;
            }
        }
        printf("  SHA-256 known-answer tests OK\n");
    }
    uint64_t t = cycles_now();
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, buf, sizeof buf);
    wc_Sha256Final(&sha, digest);
    row("SHA-256, 1 KB", cycles_now() - t);

#ifdef HAVE_AESGCM
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    t = cycles_now();
    wc_AesGcmSetKey(&aes, key, sizeof key);
    row("AES-128-GCM key setup", cycles_now() - t);
    t = cycles_now();
    if (wc_AesGcmEncrypt(&aes, out, buf, sizeof buf, iv, sizeof iv, tag, sizeof tag, NULL, 0))
        return -1;
    row("AES-128-GCM encrypt, 1 KB", cycles_now() - t);
    wc_AesFree(&aes);
#else
    (void)aes; (void)key;
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    {
        byte k32[32] = {3};
        t = cycles_now();
        if (wc_ChaCha20Poly1305_Encrypt(k32, iv, NULL, 0, buf, sizeof buf, out, tag))
            return -1;
        row("ChaCha20-Poly1305 encrypt, 1 KB", cycles_now() - t);
    }
#endif
    return 0;
}

static int bench_mlkem(WC_RNG *rng)
{
    static MlKemKey key;
    static byte ct[WC_ML_KEM_512_CIPHER_TEXT_SIZE];
    byte ss1[32], ss2[32];
    uint64_t t;

    if (wc_MlKemKey_Init(&key, WC_ML_KEM_512, NULL, INVALID_DEVID))
        return -1;
    t = cycles_now();
    if (wc_MlKemKey_MakeKey(&key, rng)) return -1;
    row("ML-KEM-512 keygen", cycles_now() - t);
    t = cycles_now();
    if (wc_MlKemKey_Encapsulate(&key, ct, ss1, rng)) return -1;
    row("ML-KEM-512 encaps", cycles_now() - t);
    t = cycles_now();
    if (wc_MlKemKey_Decapsulate(&key, ss2, ct, sizeof ct)) return -1;
    row("ML-KEM-512 decaps", cycles_now() - t);
    wc_MlKemKey_Free(&key);
    return memcmp(ss1, ss2, sizeof ss1) ? -1 : 0;
}

static int bench_mldsa(WC_RNG *rng)
{
    static dilithium_key key;
    static byte sig[DILITHIUM_LEVEL2_SIG_SIZE];
    static const byte msg[64] = "TLS 1.3, client CertificateVerify (transcript hash)";
    word32 siglen;
    int res = 0;
    uint64_t t, mn = ~0ull, mx = 0, sum = 0;

    if (wc_dilithium_init(&key) || wc_dilithium_set_level(&key, WC_ML_DSA_44))
        return -1;
    /* Fixed key seed: the number of signing rejection rounds depends on
     * key and message, so a fixed key keeps sign timings comparable
     * between builds. */
    static const byte kseed[32] = { 0x42 };
    (void)rng;
    t = cycles_now();
    if (wc_dilithium_make_key_from_seed(&key, kseed)) return -1;
    row("ML-DSA-44 keygen", cycles_now() - t);

    extern uint32_t metrics_keccak_calls;
    for (int i = 0; i < SIGN_SEEDS; i++) {
        byte seed[32];
        memset(seed, i + 1, sizeof seed);
        siglen = sizeof sig;
        uint32_t k0 = metrics_keccak_calls;
        t = cycles_now();
        if (wc_dilithium_sign_msg_with_seed(msg, sizeof msg, sig, &siglen, &key, seed))
            return -1;
        t = cycles_now() - t;
        {
            byte d[32];
            wc_Sha256 h;
            wc_InitSha256(&h);
            wc_Sha256Update(&h, sig, siglen);
            wc_Sha256Final(&h, d);
            printf("    sign seed %d: %8lu cycles, %4lu Keccak-f calls, sig sha256 %02x%02x%02x%02x%02x%02x%02x%02x\n",
                   i + 1, (unsigned long)t, (unsigned long)(metrics_keccak_calls - k0),
                   d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
        }
        sum += t;
        if (t < mn) mn = t;
        if (t > mx) mx = t;
    }
    row("ML-DSA-44 sign (min)", mn);
    row("ML-DSA-44 sign (avg of 8 seeds)", sum / SIGN_SEEDS);
    row("ML-DSA-44 sign (max)", mx);

    t = cycles_now();
    if (wc_dilithium_verify_msg(sig, siglen, msg, sizeof msg, &res, &key) || res != 1)
        return -1;
    row("ML-DSA-44 verify", cycles_now() - t);
    wc_dilithium_free(&key);
    return 0;
}

/* Per-instruction cost of the multiplier: 8 dependent-free ops per loop. */
static void bench_mul(void)
{
    uint32_t a = 0x12345678, b = 0x9abcdef1, r0 = 0, r1 = 0;
    const int n = 256;
    uint64_t t = cycles_now();
    for (int i = 0; i < n; i++)
        __asm__ volatile ("mul %0,%2,%3\n mul %1,%2,%3\n mul %0,%2,%3\n mul %1,%2,%3\n"
                          "mul %0,%2,%3\n mul %1,%2,%3\n mul %0,%2,%3\n mul %1,%2,%3"
                          : "=&r"(r0), "=&r"(r1) : "r"(a), "r"(b));
    uint64_t c_mul = cycles_now() - t;
    t = cycles_now();
    for (int i = 0; i < n; i++)
        __asm__ volatile ("mulh %0,%2,%3\n mulh %1,%2,%3\n mulh %0,%2,%3\n mulh %1,%2,%3\n"
                          "mulh %0,%2,%3\n mulh %1,%2,%3\n mulh %0,%2,%3\n mulh %1,%2,%3"
                          : "=&r"(r0), "=&r"(r1) : "r"(a), "r"(b));
    uint64_t c_mulh = cycles_now() - t;
    t = cycles_now();
    for (int i = 0; i < n; i++)
        __asm__ volatile ("add %0,%2,%3\n add %1,%2,%3\n add %0,%2,%3\n add %1,%2,%3\n"
                          "add %0,%2,%3\n add %1,%2,%3\n add %0,%2,%3\n add %1,%2,%3"
                          : "=&r"(r0), "=&r"(r1) : "r"(a), "r"(b));
    uint64_t c_add = cycles_now() - t;
    printf("  cycles per instr (x100): add %lu, mul %lu, mulh %lu\n",
           (unsigned long)(c_add * 100 / (8 * n)), (unsigned long)(c_mul * 100 / (8 * n)),
           (unsigned long)(c_mulh * 100 / (8 * n)));
    (void)r0; (void)r1;
}

/* Memory system: cost per load when every load misses the D-cache (stride
 * = 32 B line, 32 KB span) vs when 8 consecutive words share a line. */
static void bench_mem(void)
{
    static volatile uint32_t buf[8192];             /* 32 KB */
    uint32_t sum = 0;
    for (int i = 0; i < 8192; i += 8) sum += buf[i];  /* warm TLB-less path */
    uint64_t t = cycles_now();
    for (int i = 0; i < 8192; i += 8) sum += buf[i];
    uint64_t miss = cycles_now() - t;
    t = cycles_now();
    for (int i = 0; i < 8192; i++) sum += buf[i];
    uint64_t seq = cycles_now() - t;
    t = cycles_now();
    for (int i = 0; i < 1024; i++) sum += buf[i & 255];   /* 1 KB: all hits */
    uint64_t hit = cycles_now() - t;
    t = cycles_now();
    for (int i = 0; i < 1024; i++) buf[i] = i;            /* stores, 4 KB */
    uint64_t st = cycles_now() - t;
    printf("  load, every one a miss:      %4lu cycles\n", (unsigned long)(miss / 1024));
    printf("  load, sequential (x100):     %4lu cycles\n", (unsigned long)(seq * 100 / 8192));
    printf("  load, cache hit (x100):      %4lu cycles\n", (unsigned long)(hit * 100 / 1024));
    printf("  store, sequential (x100):    %4lu cycles\n", (unsigned long)(st * 100 / 1024));
    (void)sum;
}

#ifdef BENCH_PQRV_NTT
/* PQRV single-issue RV32IM NTT vs the pq-crystals reference C NTT (which
 * wolfCrypt's C NTT implements): speed, and equality modulo q. */
#define DQ 8380417
extern int32_t zetas_ntt_8l_rv32im[512], zetas_intt_8l_rv32im[512];
extern const int32_t ref_zetas[256];
extern void ntt_8l_rv32im(int32_t *r, int32_t *zetas);
extern void intt_8l_rv32im(int32_t *r, int32_t *zetas);

static int32_t ref_mont(int64_t a)
{
    int32_t t = (int32_t)((int32_t)a * 58728449);
    return (int32_t)((a - (int64_t)t * DQ) >> 32);
}
static void ref_ntt(int32_t a[256])
{
    unsigned len, start, j, k = 0;
    for (len = 128; len > 0; len >>= 1)
        for (start = 0; start < 256; start = j + len) {
            int32_t zeta = ref_zetas[++k];
            for (j = start; j < start + len; ++j) {
                int32_t t = ref_mont((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
}
static void ref_intt(int32_t a[256])
{
    unsigned start, len, j, k = 256;
    for (len = 1; len < 256; len <<= 1)
        for (start = 0; start < 256; start = j + len) {
            int32_t zeta = -ref_zetas[--k];
            for (j = start; j < start + len; ++j) {
                int32_t t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = ref_mont((int64_t)zeta * a[j + len]);
            }
        }
    for (j = 0; j < 256; ++j)
        a[j] = ref_mont((int64_t)41978 * a[j]);
}
static int32_t modq(int32_t x) { x %= DQ; return x < 0 ? x + DQ : x; }

static void bench_pqrv_ntt(void)
{
    static int32_t a[256], b[256];
    uint32_t seed = 12345;
    for (int i = 0; i < 256; i++) {
        seed = seed * 1103515245u + 12345u;
        a[i] = b[i] = (int32_t)(seed % DQ) - DQ / 2;
    }
    uint64_t t = cycles_now(); ref_ntt(a); uint64_t c_ref = cycles_now() - t;
    t = cycles_now(); ntt_8l_rv32im(b, zetas_ntt_8l_rv32im); uint64_t c_asm = cycles_now() - t;
    int same = 1;
    for (int i = 0; i < 256; i++) same &= modq(a[i]) == modq(b[i]);
    printf("  NTT  ref C %6lu, PQRV asm %6lu cycles, outputs equal mod q: %s\n",
           (unsigned long)c_ref, (unsigned long)c_asm, same ? "yes" : "NO");
    for (int i = 0; i < 256; i++) b[i] = a[i] = modq(a[i]) - DQ / 2;
    t = cycles_now(); ref_intt(a); c_ref = cycles_now() - t;
    t = cycles_now(); intt_8l_rv32im(b, zetas_intt_8l_rv32im); c_asm = cycles_now() - t;
    same = 1;
    for (int i = 0; i < 256; i++) same &= modq(a[i]) == modq(b[i]);
    printf("  INTT ref C %6lu, PQRV asm %6lu cycles, outputs equal mod q: %s\n",
           (unsigned long)c_ref, (unsigned long)c_asm, same ? "yes" : "NO");
}
#endif

int bench_run(void)
{
    WC_RNG rng;
    int rc = 0;

    printf("\n=== crypto microbenchmarks (cycles) ===\n");
    if (wc_InitRng(&rng))
        return -1;
    bench_mul();
    bench_mem();
#ifdef BENCH_PQRV_NTT
    bench_pqrv_ntt();
#endif
    if (bench_keccak() || bench_sym()) { printf("hash/aes failed\n"); rc = -1; }
    if (bench_mlkem(&rng)) { printf("ML-KEM failed\n"); rc = -1; }
    if (bench_mldsa(&rng)) { printf("ML-DSA failed\n"); rc = -1; }
    wc_FreeRng(&rng);
    printf("=== bench %s ===\n", rc ? "FAILED" : "DONE");
    return rc;
}
