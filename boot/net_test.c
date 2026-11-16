/*
 * net_test.c - UDP echo self-test for the Ethernet transport (net.c).
 *
 * Sends datagrams of increasing size to the host echo server
 * (scripts/udp_echo.py), checks each reply byte-for-byte, and reports
 * the round-trip time in CPU cycles.
 */
#include "net.h"
#include "timing.h"

#include <stdio.h>
#include <string.h>

#define LOCAL_PORT  11112
#define REMOTE_PORT 11111

int net_echo_test(void)
{
    static uint8_t tx[NET_MAX_PAYLOAD], rx[NET_MAX_PAYLOAD];
    static const uint32_t sizes[] = {16, 256, 1024, NET_MAX_PAYLOAD};
    int failures = 0;

    printf("\n=== UDP echo test ===\n");

    uint64_t c0 = cycles_now(), c1 = cycles_now();
    printf("cycle counter: %lu -> %lu\n", (unsigned long)c0, (unsigned long)c1);
    if (c1 <= c0) {
        printf("cycle counter not advancing!\n");
        return -1;
    }

    if (net_init(LOCAL_PORT, REMOTE_PORT) != 0) {
        printf("ARP resolution of remote failed (is tap0 up?)\n");
        return -1;
    }
    printf("remote resolved, local :%d -> remote :%d\n", LOCAL_PORT, REMOTE_PORT);

    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        uint32_t n = sizes[i];
        for (uint32_t j = 0; j < n; j++)
            tx[j] = (uint8_t)(j * 7 + i);

        uint64_t t0 = cycles_now();
        if (net_send(tx, n) != (int)n) {
            printf("[%4lu B] send failed\n", (unsigned long)n);
            failures++;
            continue;
        }
        int r = net_recv(rx, sizeof(rx), 5000);
        uint64_t dt = cycles_now() - t0;

        if (r == (int)n && memcmp(tx, rx, n) == 0) {
            printf("[%4lu B] echo OK, RTT %lu cycles\n",
                   (unsigned long)n, (unsigned long)dt);
        } else {
            printf("[%4lu B] echo FAILED (recv returned %d)\n", (unsigned long)n, r);
            failures++;
        }
    }

    const struct net_stats *s = net_get_stats();
    printf("tx %lu pkts / %lu B, rx %lu pkts / %lu B, dropped: queue %lu, foreign %lu\n",
           (unsigned long)s->tx_packets, (unsigned long)s->tx_bytes,
           (unsigned long)s->rx_packets, (unsigned long)s->rx_bytes,
           (unsigned long)s->rx_dropped_queue_full, (unsigned long)s->rx_dropped_foreign);
    printf("=== UDP echo test %s ===\n", failures ? "FAILED" : "PASSED");
    return failures ? -1 : 0;
}
