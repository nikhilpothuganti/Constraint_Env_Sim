/*
 * net.h - minimal datagram transport for the bare-metal DTLS client.
 *
 * Small self-contained Ethernet/ARP/IPv4/UDP layer on the LiteEth MAC,
 * single remote peer, with datagram semantics: each net_recv() returns
 * exactly one UDP payload, which is what DTLS expects from its transport.
 *
 * Reception is interrupt driven: the ETHMAC ISR copies each frame out of
 * the MAC's two hardware RX slots into a 16-frame software ring at once,
 * so back-to-back server flights are not dropped while the CPU is busy
 * with PQC crypto. The ISR also answers ARP requests itself, so the host
 * can always reach us. UDP parsing/sending happen in main context.
 */
#ifndef NET_H
#define NET_H

#include <stdint.h>

/* Largest UDP payload we can send/receive: 1500-byte Ethernet MTU minus
 * 20-byte IPv4 header and 8-byte UDP header. libliteeth sets DF and does
 * no IP fragmentation, so DTLS must fragment to fit (wolfSSL_dtls_set_mtu). */
#define NET_MAX_PAYLOAD 1472

/* Enable the Ethernet RX interrupt and ARP-resolve the remote peer.
 * Addresses come from the SoC build (--local-ip / --remote-ip).
 * Returns 0 on success, -1 if the remote did not answer ARP. */
int net_init(uint16_t local_port, uint16_t remote_port);

/* Send one datagram to the remote peer. Returns len, or -1 on error. */
int net_send(const void *buf, uint32_t len);

/* Receive one datagram, waiting up to timeout_ms (0 = just poll once).
 * Returns the datagram length, 0 on timeout, or -1 if buf is too small
 * (the datagram is dropped, as a UDP socket would truncate it). */
int net_recv(void *buf, uint32_t maxlen, uint32_t timeout_ms);

/* Process pending non-data frames (e.g. answer ARP requests). */
void net_poll(void);

/* Counters for diagnostics. */
struct net_stats {
    uint32_t tx_packets, tx_bytes;
    uint32_t rx_packets, rx_bytes;
    uint32_t rx_dropped_queue_full;   /* software RX ring overflow */
    uint32_t rx_dropped_hw;           /* MAC had no free RX slot (LiteEth
                                         sram_writer errors counter) */
    uint32_t rx_dropped_foreign;      /* wrong source IP/port      */
    uint32_t arp_replies;             /* ARP requests answered (ISR) */
    uint32_t isr_max_cycles;          /* longest Ethernet ISR run */
};
const struct net_stats *net_get_stats(void);

/* UDP echo self-test against scripts/udp_echo.py (net_test.c).
 * Returns 0 if every echo came back intact. */
int net_echo_test(void);

#endif /* NET_H */
