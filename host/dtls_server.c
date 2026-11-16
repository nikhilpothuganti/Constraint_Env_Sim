/*
 * dtls_server.c - host-side PQC DTLS 1.3 server for the RISC-V client.
 *
 * Runs on Linux (the VM) with native wolfSSL 5.8.4. For each client:
 *   - DTLS 1.3 only, HelloRetryRequest cookie (stateless, anti-DoS)
 *   - key exchange: ML-KEM (groups configurable)
 *   - mutual authentication: ML-DSA server cert; a client cert signed
 *     by the CA is REQUIRED (handshake fails without one)
 *   - echoes every application record back until close_notify
 *
 * usage: dtls_server [-p port] [-d certdir] [-k ML_KEM_512|ML_KEM_768|ML_KEM_1024]
 *                    [-n connections (0 = forever)] [-T initial_timeout_s] [-v]
 *
 * -T: initial DTLS retransmission timeout. The simulated device runs at
 *     ~2M cycles per wall-clock second, far slower than real hardware, so
 *     the default 1 s host timer fires while the device is still computing
 *     and it then has to process duplicate flights. A larger value removes
 *     this simulation artifact from the measurements.
 */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static int kem_by_name(const char *s)
{
    if (!strcmp(s, "ML_KEM_512"))  return WOLFSSL_ML_KEM_512;
    if (!strcmp(s, "ML_KEM_768"))  return WOLFSSL_ML_KEM_768;
    if (!strcmp(s, "ML_KEM_1024")) return WOLFSSL_ML_KEM_1024;
    fprintf(stderr, "unknown KEM %s\n", s);
    exit(2);
}

int main(int argc, char **argv)
{
    int port = 11111, conns = 0, verbose = 0, timeout_init = 0, opt;
    const char *dir = "certs/mldsa44";
    int groups[3] = { WOLFSSL_ML_KEM_512, WOLFSSL_ML_KEM_768, WOLFSSL_ML_KEM_1024 };
    int ngroups = 3;
    char path[3][512];

    while ((opt = getopt(argc, argv, "p:d:k:n:T:v")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 'd': dir = optarg; break;
        case 'k': groups[0] = kem_by_name(optarg); ngroups = 1; break;
        case 'n': conns = atoi(optarg); break;
        case 'T': timeout_init = atoi(optarg); break;
        case 'v': verbose = 1; break;
        default:
            fprintf(stderr, "usage: %s [-p port] [-d certdir] [-k KEM] [-n conns] [-T secs] [-v]\n", argv[0]);
            return 2;
        }
    }
    snprintf(path[0], sizeof path[0], "%s/server-cert.pem", dir);
    snprintf(path[1], sizeof path[1], "%s/server-key.pem", dir);
    snprintf(path[2], sizeof path[2], "%s/ca-cert.pem", dir);

    wolfSSL_Init();
    if (verbose) wolfSSL_Debugging_ON();

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx ||
        wolfSSL_CTX_use_certificate_file(ctx, path[0], WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, path[1], WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_load_verify_locations(ctx, path[2], NULL) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to set up context / load credentials from %s\n", dir);
        return 1;
    }
    /* Mutual authentication: client certificate required. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (wolfSSL_CTX_set_groups(ctx, groups, ngroups) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to set ML-KEM groups\n");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port),
                                .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        return 1;
    }
    printf("dtls_server: listening on udp/%d, certs %s, %d KEM group(s)\n", port, dir, ngroups);
    fflush(stdout);

    for (int served = 0; conns == 0 || served < conns; served++) {
        /* Wait for the first datagram of a new client to learn its address. */
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        char b;
        if (recvfrom(fd, &b, 1, MSG_PEEK, (struct sockaddr *)&peer, &plen) < 0) {
            perror("recvfrom");
            break;
        }
        printf("\n[conn %d] client %s:%d\n", served, inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

        WOLFSSL *ssl = wolfSSL_new(ctx);
        wolfSSL_dtls_set_peer(ssl, &peer, plen);
        wolfSSL_set_fd(ssl, fd);
        if (timeout_init > 0)
            wolfSSL_dtls_set_timeout_init(ssl, timeout_init);

        double t0 = now_ms();
        if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, 0);
            char es[80];
            printf("[conn %d] handshake FAILED: %d (%s)\n", served, err,
                   wolfSSL_ERR_error_string(err, es));
            wolfSSL_free(ssl);
            continue;
        }
        double t1 = now_ms();

        WOLFSSL_X509 *pc = wolfSSL_get_peer_certificate(ssl);
        const char *cn = pc ? wolfSSL_X509_get_subjectCN(pc) : NULL;
        if (!cn) cn = "?";
        printf("[conn %d] handshake OK in %.1f ms (wall)\n", served, t1 - t0);
        printf("[conn %d]   version %s, cipher %s, group %s\n", served,
               wolfSSL_get_version(ssl), wolfSSL_get_cipher_name(ssl),
               wolfSSL_get_curve_name(ssl));
        printf("[conn %d]   client authenticated: CN=%s\n", served, cn);
        fflush(stdout);

        /* Echo records until the client closes. */
        char buf[16384];
        int n, msgs = 0, bulk_recs = 0;
        long bytes = 0, bulk = 0;
        double tb0 = 0;
        while ((n = wolfSSL_read(ssl, buf, sizeof buf)) > 0) {
            /* Throughput test: "#BULK..." records are counted, not echoed;
             * "#END" is answered with the byte count. */
            if (n >= 5 && !memcmp(buf, "#BULK", 5)) {
                if (!bulk_recs++) tb0 = now_ms();
                bulk += n;
                continue;
            }
            if (n == 4 && !memcmp(buf, "#END", 4)) {
                int m = snprintf(buf, sizeof buf, "#GOT %ld B in %d records", bulk, bulk_recs);
                printf("[conn %d]   bulk: %ld B in %d records over %.1f ms (wall)\n",
                       served, bulk, bulk_recs, now_ms() - tb0);
                fflush(stdout);
                if (wolfSSL_write(ssl, buf, m) != m)
                    break;
                continue;
            }
            msgs++;
            bytes += n;
            if (n <= 80)
                printf("[conn %d]   rx %d B: \"%.*s\"\n", served, n, n, buf);
            fflush(stdout);
            if (wolfSSL_write(ssl, buf, n) != n)
                break;
        }
        printf("[conn %d] closed after %d messages, %ld bytes echoed\n", served, msgs, bytes);
        fflush(stdout);
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }

    close(fd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
