/*
 * dtls_client.c - PQC DTLS 1.3 client with mutual authentication.
 *
 *   transport      UDP datagrams via net.c (device 192.168.1.50:11112 ->
 *                  server 192.168.1.100:11111)
 *   key exchange   ML-KEM only (no classical fallback offered)
 *   authentication server: ML-DSA cert chain verified against the
 *                  embedded CA; client: embedded ML-DSA cert + key
 *
 * After the handshake, a few application messages are exchanged and the
 * cycle counts of each phase are reported.
 */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <string.h>

#include "dtls_client.h"
#include "net.h"
#include "timing.h"
#include "certs.h"
#include "metrics.h"

#define CLIENT_PORT 11112
#define SERVER_PORT 11111
#define SERVER_NAME "pqc-dtls-server"     /* must match the server cert CN */
#define KEM_GROUP   WOLFSSL_ML_KEM_512

/* Initial DTLS retransmission timeout (seconds of device time). The 1 s
 * default assumes a fast peer; this client needs several seconds of CPU
 * for ML-KEM/ML-DSA and record crypto per flight, and would otherwise
 * retransmit while still working. RFC 7925 (TLS/DTLS IoT profile) likewise
 * recommends a larger initial timer for constrained nodes. */
#define DTLS_TIMEOUT_INIT_S 4

/* Gap timer. wolfSSL asks for a "quick timeout" once part of the peer's
 * flight has arrived. If the rest does not follow within this time we
 * return a timeout, wolfSSL ACKs what it has (RFC 9147 sec. 7.1), and the
 * peer resends only the missing records. wolfSSL's own hint is 1/4 of the
 * retransmission timer (1 s here), which made every lost record cost ~1M
 * cycles of idling. The rest of a flight follows within a few ms, so
 * 50 ms is ample. Losses happen: the LiteEth MAC has only 2 RX slots, so a
 * third back-to-back frame is dropped if it arrives while the ISR is
 * still copying the first. */
#define DTLS_GAP_ACK_MS 50

/* Throughput phase: BULK_RECORDS one-way records of BULK_SIZE bytes, then
 * the server reports how many bulk bytes it received ("#GOT n"). A record
 * of ~1400 B plus DTLS overhead fills one 1472-byte datagram. */
#define BULK_RECORDS 48
#define BULK_SIZE    1400

/* ------------------------------------------------- I/O callbacks (net.c) */

#ifdef DTLS_TRACE
/* One line per datagram: cycle stamp (k), direction, size, first header
 * byte (0x16 handshake / 0x17 app / 0x15 alert / 0x2x unified header with
 * epoch low bits / 0x1a ACK in clear). Cheap enough to keep timing realistic. */
#define TRACE(...) printf(__VA_ARGS__)
#else
#define TRACE(...) do { } while (0)
#endif

static int io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl; (void)ctx;
    int r = net_send(buf, (uint32_t)sz);
    TRACE("[%9lu k] TX %4d B hdr %02x\n", (unsigned long)(cycles_now() / 1000),
          sz, (unsigned char)buf[0]);
    return r < 0 ? WOLFSSL_CBIO_ERR_GENERAL : r;
}

/* Blocks for one datagram until the current DTLS retransmission timeout.
 * Returning WOLFSSL_CBIO_ERR_TIMEOUT makes wolfSSL retransmit its last
 * flight, as with a socket receive timeout. */
static int io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ctx;
    uint32_t timeout_ms = (uint32_t)wolfSSL_dtls_get_current_timeout(ssl) * 1000;
#ifdef WOLFSSL_DTLS13
    if (wolfSSL_dtls13_use_quick_timeout(ssl) && timeout_ms > DTLS_GAP_ACK_MS)
        timeout_ms = DTLS_GAP_ACK_MS;   /* partial flight: ACK the gap soon */
#endif
    uint64_t t0 = cycles_now();
    int r = net_recv(buf, (uint32_t)sz, timeout_ms);
    metrics_wait_cycles += cycles_now() - t0;
    TRACE("[%9lu k] RX %4d B hdr %02x (timeout %lu ms, dropped %lu)\n",
          (unsigned long)(cycles_now() / 1000), r, r > 0 ? (unsigned char)buf[0] : 0,
          (unsigned long)timeout_ms, (unsigned long)net_get_stats()->rx_dropped_queue_full);
    if (r == 0)
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    if (r < 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;   /* oversized datagram dropped */
    return r;
}

/* ----------------------------------------------------------- helpers */

#ifdef DTLS_DEBUG
/* wolfSSL log lines, prefixed with the cycle counter (in thousands). */
static void log_cb(const int level, const char *msg)
{
    (void)level;
    printf("[%9lu k] %s\n", (unsigned long)(cycles_now() / 1000), msg);
}
#endif

static void print_cycles(const char *what, uint64_t c)
{
    printf("  %-28s %10lu cycles (%lu ms @ %lu MHz)\n", what,
           (unsigned long)c,
           (unsigned long)(c / (CONFIG_CLOCK_FREQUENCY / 1000)),
           (unsigned long)(CONFIG_CLOCK_FREQUENCY / 1000000));
}

static int load_credentials(WOLFSSL_CTX *ctx)
{
    int ret;
    if ((ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_cert_der, sizeof(ca_cert_der),
                                              WOLFSSL_FILETYPE_ASN1)) != WOLFSSL_SUCCESS) {
        printf("load CA failed: %d\n", ret);
        return -1;
    }
#ifndef DTLS_NO_PIN
    /* Pinned server certificate: if the server presents exactly this
     * certificate, wolfSSL trusts it without re-checking the CA's signature
     * on it (saves one ML-DSA verify). The server still proves possession
     * of the key in CertificateVerify, and the hostname is still checked.
     * Any other certificate goes through normal CA validation. */
    if ((ret = wolfSSL_CTX_trust_peer_buffer(ctx, server_cert_der, sizeof(server_cert_der),
                                             WOLFSSL_FILETYPE_ASN1)) != WOLFSSL_SUCCESS) {
        printf("load pinned server cert failed: %d\n", ret);
        return -1;
    }
#endif
#ifdef DTLS_NO_CLIENT_CERT
    /* Negative test build: present no certificate; the server must refuse. */
    printf("WARNING: test build without client certificate\n");
    return 0;
#endif
    if ((ret = wolfSSL_CTX_use_certificate_buffer(ctx, client_cert_der, sizeof(client_cert_der),
                                                  WOLFSSL_FILETYPE_ASN1)) != WOLFSSL_SUCCESS) {
        printf("load client cert failed: %d\n", ret);
        return -1;
    }
    if ((ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, client_key_der, sizeof(client_key_der),
                                                 WOLFSSL_FILETYPE_ASN1)) != WOLFSSL_SUCCESS) {
        printf("load client key failed: %d\n", ret);
        return -1;
    }
    return 0;
}

/* Run one wolfSSL operation to completion, retrying on WANT_READ/WRITE. */
#define DTLS_RETRY(ssl, call, ret, err)                                      \
    do {                                                                     \
        (ret) = (call);                                                      \
        (err) = ((ret) > 0) ? 0 : wolfSSL_get_error((ssl), (ret));           \
    } while ((err) == WOLFSSL_ERROR_WANT_READ || (err) == WOLFSSL_ERROR_WANT_WRITE)

/* One-way bulk transfer, then ask the server how much arrived (app data
 * records are not retransmitted by DTLS, so loss would show up here). */
static int bulk_send(WOLFSSL *ssl)
{
    static char blk[BULK_SIZE];
    char reply[64];
    int ret, err;

    memset(blk, 'x', sizeof blk);
    memcpy(blk, "#BULK", 5);
    uint64_t t0 = cycles_now();
    for (int i = 0; i < BULK_RECORDS; i++) {
        DTLS_RETRY(ssl, wolfSSL_write(ssl, blk, sizeof blk), ret, err);
        if (ret != (int)sizeof blk) {
            printf("bulk write %d failed: error %d\n", i, err);
            return -1;
        }
    }
    uint64_t t1 = cycles_now();
    DTLS_RETRY(ssl, wolfSSL_write(ssl, "#END", 4), ret, err);
    DTLS_RETRY(ssl, wolfSSL_read(ssl, reply, sizeof reply - 1), ret, err);
    if (ret <= 0) {
        printf("bulk: no reply from server (error %d)\n", err);
        return -1;
    }
    reply[ret] = '\0';
    unsigned long sent = (unsigned long)BULK_RECORDS * BULK_SIZE;
    unsigned long c = (unsigned long)(t1 - t0);
    printf("throughput: %lu B in %d records, %lu cycles -> %lu cycles/B, "
           "%lu B/s @ %lu MHz; server: %s\n",
           sent, BULK_RECORDS, c, c / sent,
           (unsigned long)((uint64_t)sent * CONFIG_CLOCK_FREQUENCY / c),
           (unsigned long)(CONFIG_CLOCK_FREQUENCY / 1000000), reply);
    return 0;
}

/* -------------------------------------------------------------- client */

int dtls_client_run(int messages)
{
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    int ret, err, rc = -1;
    char msg[64], reply[256];

    printf("\n=== PQC DTLS 1.3 client ===\n");

    if (net_init(CLIENT_PORT, SERVER_PORT) != 0) {
        printf("network: server 192.168.1.100 did not answer ARP\n");
        return -1;
    }

    uint64_t t_init = cycles_now();
    metrics_phase_reset();      /* ML-KEM keygen happens in UseKeyShare (setup) */
    wolfSSL_Init();
#ifdef DTLS_DEBUG
    wolfSSL_SetLoggingCb(log_cb);
    wolfSSL_Debugging_ON();
#endif
    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) {
        printf("wolfSSL_CTX_new failed\n");
        goto out;
    }
    if (load_credentials(ctx) != 0)
        goto out;
    wolfSSL_CTX_SetIORecv(ctx, io_recv);
    wolfSSL_CTX_SetIOSend(ctx, io_send);

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        printf("wolfSSL_new failed\n");
        goto out;
    }
    wolfSSL_dtls_set_mtu(ssl, NET_MAX_PAYLOAD);
    wolfSSL_dtls_set_timeout_init(ssl, DTLS_TIMEOUT_INIT_S);
    wolfSSL_check_domain_name(ssl, SERVER_NAME);

    /* Offer exactly one group, ML-KEM, with its key share in ClientHello. */
    int groups[] = { KEM_GROUP };
    if ((ret = wolfSSL_set_groups(ssl, groups, 1)) != WOLFSSL_SUCCESS) {
        printf("wolfSSL_set_groups(ML-KEM) failed: %d\n", ret);
        goto out;
    }
    if ((ret = wolfSSL_UseKeyShare(ssl, KEM_GROUP)) != WOLFSSL_SUCCESS) {
        printf("wolfSSL_UseKeyShare(ML-KEM) failed: %d\n", ret);
        goto out;
    }
    uint64_t t_hs = cycles_now();

    printf("handshake: connecting to 192.168.1.100:%d ...\n", SERVER_PORT);
    metrics_wait_cycles = 0;
    DTLS_RETRY(ssl, wolfSSL_connect(ssl), ret, err);
    uint64_t t_done = cycles_now();
    uint64_t hs_wait = metrics_wait_cycles;
    if (ret != WOLFSSL_SUCCESS) {
        printf("handshake FAILED: ret %d, error %d\n", ret, err);
        goto out;
    }

    printf("handshake OK\n");
    printf("  version  %s\n", wolfSSL_get_version(ssl));
    printf("  cipher   %s\n", wolfSSL_get_cipher_name(ssl));
    printf("  group    %s\n", wolfSSL_get_curve_name(ssl));
    print_cycles("context setup", t_hs - t_init);
    print_cycles("handshake", t_done - t_hs);
    print_cycles("  of which waiting on net", hs_wait);
    print_cycles("  of which compute", (t_done - t_hs) - hs_wait);
    printf("  PQC operations (setup + handshake):\n");
    metrics_phase_print();
    printf("  heap peak (wolfSSL)   %6lu B through handshake, %lu B live after\n",
           (unsigned long)metrics_heap()->peak, (unsigned long)metrics_heap()->cur);

    /* Application data. */
    uint64_t t_app = cycles_now();
    for (int i = 0; i < messages; i++) {
        int n = snprintf(msg, sizeof(msg), "hello from RISC-V #%d", i);
        DTLS_RETRY(ssl, wolfSSL_write(ssl, msg, n), ret, err);
        if (ret != n) {
            printf("write %d failed: error %d\n", i, err);
            goto out;
        }
        DTLS_RETRY(ssl, wolfSSL_read(ssl, reply, sizeof(reply) - 1), ret, err);
        if (ret <= 0) {
            printf("read %d failed: error %d\n", i, err);
            goto out;
        }
        reply[ret] = '\0';
        printf("  [%d] sent \"%s\", got \"%s\"\n", i, msg, reply);
    }
    print_cycles("app data round trips", cycles_now() - t_app);

    if (bulk_send(ssl) != 0)
        goto out;

    wolfSSL_shutdown(ssl);
    rc = 0;

out:
    {
        const struct net_stats *s = net_get_stats();
        printf("net: tx %lu pkts/%lu B, rx %lu pkts/%lu B, rx dropped %lu (ring) %lu (MAC), arp replies %lu, isr max %lu cycles\n",
               (unsigned long)s->tx_packets, (unsigned long)s->tx_bytes,
               (unsigned long)s->rx_packets, (unsigned long)s->rx_bytes,
               (unsigned long)s->rx_dropped_queue_full,
               (unsigned long)s->rx_dropped_hw,
               (unsigned long)s->arp_replies, (unsigned long)s->isr_max_cycles);
    }
    printf("heap: peak %lu B (wolfSSL allocations), %lu allocs; stack peak %lu B\n",
           (unsigned long)metrics_heap()->peak, (unsigned long)metrics_heap()->allocs,
           (unsigned long)metrics_stack_peak());
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    printf("=== PQC DTLS 1.3 client %s ===\n", rc == 0 ? "DONE" : "FAILED");
    return rc;
}
