/*
 * user_settings.h - wolfSSL/wolfCrypt configuration for the bare-metal
 * RISC-V PQC-DTLS 1.3 client (LiteX VexRiscv, no OS).
 *
 * Scope: DTLS 1.3 client only, mutual authentication, post-quantum only:
 *   key exchange   ML-KEM (FIPS 203)
 *   signatures     ML-DSA (FIPS 204) certificates on both sides
 *   record cipher  ChaCha20-Poly1305, HKDF over SHA-256
 * Everything else (RSA, ECC, DH, TLS 1.2, server side...) is compiled out.
 *
 * Platform hooks live in wolf_port.c (time, entropy) and dtls_client.c
 * (datagram I/O over net.c).
 */
#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* ------------------------------------------------------------ platform */
#define SINGLE_THREADED
#define WOLFSSL_USER_IO             /* custom send/recv callbacks (net.c)  */
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define NO_FILESYSTEM               /* certs/keys are linked-in buffers    */
#define NO_WOLFSSL_DIR
#ifndef FW_NO_SMALL_STACK           /* (experiment switch) */
#define WOLFSSL_SMALL_STACK         /* large temporaries on heap, not stack */
#define WOLFSSL_SMALL_STACK_CACHE   /* ...but allocate per-object scratch
                                       (e.g. SHA-256's W[64]) once, not once
                                       per block: SHA-256 129k -> 99k cyc/KB */
#endif
#define NO_ERROR_STRINGS            /* errors are reported as numbers      */
#define NO_SESSION_CACHE            /* no in-RAM session/client caches: they
                                       are 24 KB of BSS, and a client of one
                                       server keeps its session explicitly */

/* VexRiscv traps on misaligned loads/stores (no hardware emulation, and
 * LiteX's trap handler does not emulate them either). Without these,
 * wolfSSL writes record headers with unaligned 32-bit stores (c32toa)
 * and the CPU takes mcause=6 forever. Found with debug_trap.c. */
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_GENERAL_ALIGNMENT 4

/* Time: no RTC. wolf_port.c provides LowResTimer() and
 * TimeNowInMilliseconds() from the RISC-V cycle counter, and
 * gettimeofday() = build time + uptime, so certificate validity dates are
 * still checked (no NO_ASN_TIME). */
#define USER_TICKS

/* Entropy: seed for wolfCrypt's Hash-DRBG (see wolf_port.c). */
extern int CustomRngGenerateBlock(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED CustomRngGenerateBlock

/* ------------------------------------------------------------ protocol */
#define WOLFSSL_TLS13
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_DTLS_MTU            /* wolfSSL_dtls_set_mtu(): fit 1472-byte UDP */
/* Record numbers remembered per retransmitted record (default 3). A slow
 * device reads ACKs late; once a record has been resent >3 times, ACKs for
 * its older copies no longer match, every unmatched ACK triggers another
 * fast retransmit, and the client livelocks retransmitting its last flight.
 * Costs 16 bytes per remembered number per buffered record. */
#define DTLS13_RETRANS_RN_SIZE 16
/* WOLFSSL_DTLS_CH_FRAG is server-side (accepting a fragmented ClientHello)
 * and needs the server code; the ML-KEM-512 ClientHello fits one datagram. */
#define WOLFSSL_SEND_HRR_COOKIE     /* despite the name, also builds the client
                                       side of the cookie extension: echo the
                                       server's HelloRetryRequest cookie */
#define WOLFSSL_NO_TLS12            /* DTLS 1.3 only */
#define NO_OLD_TLS
#define NO_WOLFSSL_SERVER           /* client only */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES       /* supported_groups / key_share */
#define HAVE_HKDF
/* Pinned server certificate (wolfSSL_CTX_trust_peer_buffer, dtls_client.c):
 * if the server presents exactly that certificate, the CA signature check on
 * it is skipped (one ML-DSA-44 verify, ~2.5M cycles). The server still has to
 * prove possession of its key with CertificateVerify, so authentication is
 * unchanged; any other certificate is validated against the CA as usual. */
#define WOLFSSL_TRUST_PEER_CERT

/* --------------------------------------------- post-quantum algorithms */
/* ML-KEM (Kyber) key exchange */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
#define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM

/* Only the parameter sets this device uses: ML-KEM-512 and ML-DSA-44 (NIST
 * category 1). Build with -DFW_ALL_LEVELS (make XDEFS=...) to keep
 * ML-KEM-768/1024 and ML-DSA-65/87, e.g. for security-level comparisons. */
#ifndef FW_ALL_LEVELS
#define WOLFSSL_NO_ML_KEM_768
/* ML-KEM-1024 must stay: in wolfSSL 5.8.4 TLSX_IsGroupSupported() (tls.c)
 * has the only `break` of its ML-KEM cases inside the ML-KEM-1024 #ifndef,
 * so WOLFSSL_NO_ML_KEM_1024 makes ML-KEM-512 fall through to "unsupported"
 * and wolfSSL_set_groups() fail with -173. The ML-KEM code is generic over
 * the parameter set, so this costs little ROM. */
#define WOLFSSL_NO_ML_DSA_65
#define WOLFSSL_NO_ML_DSA_87
#endif

/* ML-DSA (Dilithium) authentication: verify server chain, sign our
 * CertificateVerify. The device key is embedded in expanded-only PKCS#8
 * form (gen_certs.sh), so no key generation code is needed; with the
 * default "seed + expanded" form wolfSSL re-ran keygen at load (+3.4M
 * cycles). BENCH builds keep keygen for the microbenchmark. */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#ifndef DTLS_BENCH
#define WOLFSSL_DILITHIUM_NO_MAKE_KEY
/* (WOLFSSL_DILITHIUM_ASSIGN_KEY would avoid copying key bytes into
 * dilithium_key, whose buffers are sized for ML-DSA-87: 7.9 KB per key
 * object. Tried: the server certificate then fails to verify (-229), as a
 * key buffer does not outlive the key object in wolfSSL's TLS path.) */
#endif
/* Verify row by row instead of holding the whole matrix A (16 KB): measured
 * no slower here (2.5M cycles per verify either way). */
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
/* Our dilithium.c patch: pad the signing scratch buffers so they do not all
 * alias in the direct-mapped 4 KB D-cache (avg sign -8%, +320 B heap). */
#define DILITHIUM_SIGN_PAD_WORDS 8
/* `make LOWMEM=1`: also sign with small memory. Heap peak 95 KB -> 61 KB,
 * but the average ML-DSA-44 signature costs ~2x (A is re-expanded on every
 * rejection-loop iteration): 7.4M -> 14.7M cycles. */
#ifdef FW_LOWMEM
#define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#endif

/* SHA-3 / SHAKE: used by both ML-KEM and ML-DSA */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* ------------------------------------------------ symmetric / hashing */
/* Record protection: TLS_CHACHA20_POLY1305_SHA256 only (RFC 8446 suite,
 * also used for DTLS 1.3 record-number encryption). Measured on this core
 * (bench.c, 1 KB): ChaCha20-Poly1305 87 cycles/B vs AES-128-GCM 320
 * cycles/B. AES's 4 KB of T-tables fill the whole 4 KB direct-mapped
 * D-cache and fight with every other access; ChaCha20 and Poly1305 are
 * 32-bit add/rotate/xor and 32x32 multiplies, no tables, and constant time
 * (no cache-timing leak, unlike table AES). The history of this choice:
 * AES-256-GCM-SHA384 -> AES-128-GCM-SHA256 (-33% handshake: SHA-384 is
 * 64-bit arithmetic on a 32-bit core) -> ChaCha20-Poly1305-SHA256.
 * ML-KEM-512 / ML-DSA-44 are NIST category 1, matching a 128-bit symmetric
 * level (ChaCha20's 256-bit key exceeds it). No AES-GCM suite is built.
 * Plain AES-128 stays compiled only because wolfSSL 5.8.4's dtls13.c
 * references it without a NO_AES guard; it is never called at runtime. */
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_AES_128
#define NO_AES_192
#define NO_AES_256
#define WC_NO_CACHE_RESISTANT       /* (only matters if AES were used) */

/* ----------------------------------------------- compiled out entirely */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_DES3
/* NO_PSK is NOT defined: TLS 1.3 session resumption is PSK-based. */

/* ECC is compiled in but never negotiated (only ML-KEM is offered, both
 * certs are ML-DSA). wolfSSL 5.8.4 cannot build TLS with ML-DSA alone:
 * WOLFSSL::pkCurveOID, used by the ML-DSA sig-algo matching, only exists
 * with ECC/EdDSA, and ssl.c requires a classical key exchange.
 * TODO(optimisation): patch those guards and drop ECC to save ROM. */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
/* (HAVE_CURVE25519 / HAVE_ED25519 intentionally not defined) */

/* ---------------------------------------------------------- debugging */
/* wolfSSL logging only in `make DEBUG=1` builds (code + strings ~ROM). */
#ifdef FW_WOLFSSL_DEBUG
#define DEBUG_WOLFSSL
#endif

#endif /* USER_SETTINGS_H */
