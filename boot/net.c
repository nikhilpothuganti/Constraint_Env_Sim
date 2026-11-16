/*
 * net.c - minimal Ethernet / ARP / IPv4 / UDP datagram transport (see net.h).
 *
 * Talks to the LiteEth MAC directly instead of using libliteeth, so that
 * reception can be interrupt driven:
 *
 *   ETHMAC IRQ ──► eth_isr(): copy frame out of the MAC RX slot into a
 *                  software ring, release the slot (no parsing, no TX).
 *   main context ─► net_recv()/net_poll(): parse frames from the ring,
 *                  answer ARP, hand matching UDP payloads to the caller.
 *
 * The MAC has only ETHMAC_RX_SLOTS (=2) hardware buffers. Without the ISR,
 * a burst of server datagrams arriving while the CPU is busy with PQC
 * crypto would overflow them and be dropped, forcing DTLS retransmissions.
 *
 * Only one remote peer is supported (the DTLS server).
 */
#include "net.h"
#include "timing.h"

#include <string.h>
#include <stdio.h>

#include <irq.h>
#include <system.h>
#include <generated/csr.h>
#include <generated/mem.h>
#include <generated/soc.h>

#ifndef CSR_ETHMAC_BASE
#error "SoC has no Ethernet MAC: build it with litex_sim --with-ethernet"
#endif
#ifndef HW_PREAMBLE_CRC
#error "net.c assumes the MAC inserts/checks preamble and CRC in hardware"
#endif

/* ---------------------------------------------------------------- frames */

#define ETH_HDR_LEN   14
#define IP_HDR_LEN    20
#define UDP_HDR_LEN   8
#define ETH_MIN_FRAME 60            /* without FCS */
#define ETH_MAX_FRAME 1514          /* without FCS */

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806
#define IP_PROTO_UDP  17

#define EV_SRAM 0x1                 /* single event bit for reader/writer */

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = (uint8_t)v; }
static inline void wr32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24; p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* --------------------------------------------------------------- state */

static const uint8_t local_mac[6] = {0x10, 0xe2, 0xd5, 0x00, 0x00, 0x00};
static uint8_t  remote_mac[6];               /* written by eth_isr() */
static volatile int remote_mac_valid;
static uint32_t local_ip, remote_ip;
static uint16_t local_port, remote_port;
static unsigned tx_slot;

static struct net_stats stats;

/* RX ring: written only by eth_isr(), read only by the main context.
 * head/tail are free-running counters; single producer + single consumer
 * on word-sized indices needs no locking on RV32. */
#define RX_RING_LEN 16              /* power of two; holds a whole server
                                       flight (~10 datagrams) that arrives
                                       while we are busy with crypto. An
                                       overflow is recovered by the DTLS gap
                                       ACK. 1.5 KB of RAM per entry. */
struct raw_frame {
    uint32_t len;
    uint8_t  data[ETH_MAX_FRAME + 2] __attribute__((aligned(4)));
};
static struct raw_frame rx_ring[RX_RING_LEN];
static volatile uint32_t rx_head, rx_tail;

static inline uint8_t *rx_slot_addr(unsigned slot)
{
    return (uint8_t *)(ETHMAC_BASE + ETHMAC_SLOT_SIZE * slot);
}
static inline uint8_t *tx_slot_addr(unsigned slot)
{
    return (uint8_t *)(ETHMAC_BASE + ETHMAC_SLOT_SIZE * (ETHMAC_RX_SLOTS + slot));
}

/* ------------------------------------------------------------------ TX */

/* TX slots are filled both from main context (UDP, ARP request) and from
 * the ISR (ARP replies). Main context therefore fills and commits a slot
 * with interrupts disabled, so the ISR never sees a half-built slot.
 * The ISR itself runs with interrupts already disabled. */
static inline unsigned tx_lock(void)
{
    unsigned ie = irq_getie();
    irq_setie(0);
    return ie;
}
static inline void tx_unlock(unsigned ie)
{
    irq_setie(ie);
}

/* Return the next free TX slot buffer (waits for the MAC to be ready). */
static uint8_t *tx_begin(void)
{
    while (!ethmac_sram_reader_ready_read())
        ;
    return tx_slot_addr(tx_slot);
}

static void tx_commit(uint32_t len)
{
    if (len < ETH_MIN_FRAME) {
        memset(tx_slot_addr(tx_slot) + len, 0, ETH_MIN_FRAME - len);
        len = ETH_MIN_FRAME;
    }
    ethmac_sram_reader_slot_write(tx_slot);
    ethmac_sram_reader_length_write(len);
    ethmac_sram_reader_start_write(1);
    tx_slot = (tx_slot + 1) % ETHMAC_TX_SLOTS;
}

static void eth_header(uint8_t *f, const uint8_t *dst, uint16_t type)
{
    memcpy(f, dst, 6);
    memcpy(f + 6, local_mac, 6);
    wr16(f + 12, type);
}

static void arp_send(uint16_t op, const uint8_t *dst_mac, uint32_t target_ip)
{
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t *f = tx_begin();
    eth_header(f, op == 1 ? bcast : dst_mac, ETHERTYPE_ARP);
    uint8_t *a = f + ETH_HDR_LEN;
    wr16(a + 0, 1);                 /* HTYPE Ethernet */
    wr16(a + 2, ETHERTYPE_IP);      /* PTYPE IPv4     */
    a[4] = 6; a[5] = 4;
    wr16(a + 6, op);                /* 1 request, 2 reply */
    memcpy(a + 8, local_mac, 6);
    wr32(a + 14, local_ip);
    if (op == 1) memset(a + 18, 0, 6); else memcpy(a + 18, dst_mac, 6);
    wr32(a + 24, target_ip);
    tx_commit(ETH_HDR_LEN + 28);
}

/* ----------------------------------------------------------------- ISR */

/* ARP is handled entirely here, not in the main loop: the host's ARP
 * cache entry for us expires every ~30-60 s, and if its re-probes go
 * unanswered (main loop busy with seconds of ML-DSA/ML-KEM work) the
 * kernel holds back every datagram to us, including the server's DTLS
 * ACKs. Answering from the ISR keeps reachability independent of crypto. */
static void arp_isr(const uint8_t *f, uint32_t len)
{
    if (len < ETH_HDR_LEN + 28)
        return;
    const uint8_t *a = f + ETH_HDR_LEN;
    uint16_t op = rd16(a + 6);
    uint32_t sender_ip = rd32(a + 14), target_ip = rd32(a + 24);
    if (target_ip != local_ip)
        return;
    if (sender_ip == remote_ip) {               /* learn/refresh peer MAC */
        memcpy(remote_mac, a + 8, 6);
        remote_mac_valid = 1;
    }
    if (op == 1) {                              /* request for our IP */
        uint8_t mac[6];
        memcpy(mac, a + 8, 6);
        arp_send(2, mac, sender_ip);
        stats.arp_replies++;
    }
}

/* Copy a frame out of a MAC slot. Both sides are word aligned; 32-bit
 * accesses (8 per iteration) instead of picolibc's -Os byte loop. This is
 * on the critical path: the MAC has only 2 RX slots, and a slot must be
 * freed before the next-but-one frame of a back-to-back burst arrives
 * (~1.4k cycles per full frame) or the MAC drops it. */
static void copy_frame(uint32_t *dst, const volatile uint32_t *src, uint32_t len)
{
    uint32_t n = (len + 3) / 4;
    while (n >= 8) {
        uint32_t a = src[0], b = src[1], c = src[2], d = src[3];
        uint32_t e = src[4], f = src[5], g = src[6], h = src[7];
        dst[0] = a; dst[1] = b; dst[2] = c; dst[3] = d;
        dst[4] = e; dst[5] = f; dst[6] = g; dst[7] = h;
        src += 8; dst += 8; n -= 8;
    }
    while (n--)
        *dst++ = *src++;
}

static void eth_isr(void)
{
    uint32_t t0 = (uint32_t)cycles_now();
    while (ethmac_sram_writer_ev_pending_read() & EV_SRAM) {
        unsigned slot = ethmac_sram_writer_slot_read();
        uint32_t len  = ethmac_sram_writer_length_read();
        const uint8_t *src = rx_slot_addr(slot);

        /* No cache flush: the MAC slots live at 0x80000000, inside
         * VexRiscv's uncached I/O region, so reads always go to the bus.
         * (A flush here also wiped the 4 KB D-cache, i.e. the crypto's
         * working set, on every received frame.) */
        if (len >= ETH_HDR_LEN && rd16(src + 12) == ETHERTYPE_ARP) {
            arp_isr(src, len);
        } else if (rx_tail - rx_head < RX_RING_LEN && len <= ETH_MAX_FRAME) {
            struct raw_frame *f = &rx_ring[rx_tail % RX_RING_LEN];
            copy_frame((uint32_t *)f->data, (const volatile uint32_t *)src, len);
            f->len = len;
            __asm__ volatile ("" ::: "memory");   /* publish data before tail */
            rx_tail++;
        } else {
            stats.rx_dropped_queue_full++;
        }
        ethmac_sram_writer_ev_pending_write(EV_SRAM);    /* free the slot */
    }
    uint32_t dt = (uint32_t)cycles_now() - t0;
    if (dt > stats.isr_max_cycles)
        stats.isr_max_cycles = dt;
}

static uint16_t ip_checksum(const uint8_t *h, unsigned len)
{
    uint32_t sum = 0;
    for (unsigned i = 0; i < len; i += 2)
        sum += rd16(h + i);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int net_send(const void *buf, uint32_t len)
{
    if (len > NET_MAX_PAYLOAD || !remote_mac_valid)
        return -1;

    unsigned ie = tx_lock();
    uint8_t *f = tx_begin();
    eth_header(f, remote_mac, ETHERTYPE_IP);

    uint8_t *ip = f + ETH_HDR_LEN;
    ip[0] = 0x45;                   /* IPv4, 20-byte header */
    ip[1] = 0;
    wr16(ip + 2, (uint16_t)(IP_HDR_LEN + UDP_HDR_LEN + len));
    wr16(ip + 4, 0);                /* identification */
    wr16(ip + 6, 0x4000);           /* don't fragment */
    ip[8] = 64;                     /* TTL */
    ip[9] = IP_PROTO_UDP;
    wr16(ip + 10, 0);
    wr32(ip + 12, local_ip);
    wr32(ip + 16, remote_ip);
    wr16(ip + 10, ip_checksum(ip, IP_HDR_LEN));

    uint8_t *udp = ip + IP_HDR_LEN;
    wr16(udp + 0, local_port);
    wr16(udp + 2, remote_port);
    wr16(udp + 4, (uint16_t)(UDP_HDR_LEN + len));
    wr16(udp + 6, 0);               /* UDP checksum optional over IPv4 (RFC 768);
                                       Ethernet FCS already protects the frame */
    memcpy(udp + UDP_HDR_LEN, buf, len);

    tx_commit(ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + len);
    tx_unlock(ie);
    stats.tx_packets++;
    stats.tx_bytes += len;
    return (int)len;
}

/* ------------------------------------------------------------------ RX */

/* Handle one frame. If it is a UDP datagram from the peer to our port,
 * copy its payload into out (up to maxlen) and return the payload length
 * (or -1 if it did not fit); with out == NULL just return 1 for such a
 * frame. Returns 0 if the frame was consumed otherwise (foreign, non-UDP...).
 * ARP never reaches the ring: eth_isr() handles it. */
static int handle_frame(const uint8_t *f, uint32_t len, uint8_t *out, uint32_t maxlen)
{
    if (len < ETH_HDR_LEN)
        return 0;
    uint16_t type = rd16(f + 12);

    if (type != ETHERTYPE_IP || len < ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)
        return 0;

    const uint8_t *ip = f + ETH_HDR_LEN;
    unsigned ihl = (ip[0] & 0x0f) * 4u;
    if ((ip[0] >> 4) != 4 || ip[9] != IP_PROTO_UDP || rd32(ip + 16) != local_ip)
        return 0;
    if (rd16(ip + 6) & 0x3fff)                  /* IP fragments unsupported */
        return 0;

    const uint8_t *udp = ip + ihl;
    uint32_t ulen = rd16(udp + 4);
    if (ulen < UDP_HDR_LEN || (uint32_t)(udp - f) + ulen > len)
        return 0;
    if (rd32(ip + 12) != remote_ip || rd16(udp + 0) != remote_port ||
        rd16(udp + 2) != local_port) {
        stats.rx_dropped_foreign++;
        return 0;
    }

    if (!out)
        return 1;                   /* peek (net_poll): leave it queued */

    uint32_t plen = ulen - UDP_HDR_LEN;
    stats.rx_packets++;
    stats.rx_bytes += plen;
    if (plen > maxlen)
        return -1;                  /* datagram truncated -> dropped */
    memcpy(out, udp + UDP_HDR_LEN, plen);
    return (int)plen;
}

/* Process queued frames. Stops at the first UDP datagram for us and
 * returns its length (>0), or -1 if it did not fit; 0 if none is queued. */
static int rx_process(uint8_t *out, uint32_t maxlen)
{
    while (rx_head != rx_tail) {
        struct raw_frame *f = &rx_ring[rx_head % RX_RING_LEN];
        int r = handle_frame(f->data, f->len, out, maxlen);
        __asm__ volatile ("" ::: "memory");
        rx_head++;                               /* hand slot back to ISR */
        if (r != 0)
            return r;
    }
    return 0;
}

void net_poll(void)
{
    /* Only foreign traffic can be consumed here; a UDP datagram for us
     * stays queued until net_recv() asks for it. */
    while (rx_head != rx_tail) {
        struct raw_frame *f = &rx_ring[rx_head % RX_RING_LEN];
        if (handle_frame(f->data, f->len, NULL, 0) == 1)
            return;
        __asm__ volatile ("" ::: "memory");
        rx_head++;
    }
}

int net_recv(void *buf, uint32_t maxlen, uint32_t timeout_ms)
{
    uint64_t deadline = cycles_now() +
        (uint64_t)timeout_ms * (CONFIG_CLOCK_FREQUENCY / 1000);
    for (;;) {
        int r = rx_process(buf, maxlen);
        if (r != 0)
            return r;
        if (cycles_now() >= deadline)
            return 0;
    }
}

/* ---------------------------------------------------------------- init */

int net_init(uint16_t lport, uint16_t rport)
{
    local_port  = lport;
    remote_port = rport;
    local_ip    = (uint32_t)LOCALIP1 << 24 | LOCALIP2 << 16 | LOCALIP3 << 8 | LOCALIP4;
    remote_ip   = (uint32_t)REMOTEIP1 << 24 | REMOTEIP2 << 16 | REMOTEIP3 << 8 | REMOTEIP4;

    /* Interrupt-driven RX. */
    ethmac_sram_reader_ev_pending_write(EV_SRAM);
    ethmac_sram_writer_ev_pending_write(EV_SRAM);
    irq_attach(ETHMAC_INTERRUPT, eth_isr);
    ethmac_sram_writer_ev_enable_write(EV_SRAM);
    irq_setmask(irq_getmask() | (1u << ETHMAC_INTERRUPT));
    irq_setie(1);

    /* Resolve the peer's MAC: up to 8 ARP requests, 100 ms apart.
     * The reply is picked up by eth_isr(). */
    for (int tries = 0; tries < 8 && !remote_mac_valid; tries++) {
        unsigned ie = tx_lock();
        arp_send(1, NULL, remote_ip);
        tx_unlock(ie);
        uint64_t deadline = cycles_now() + CONFIG_CLOCK_FREQUENCY / 10;
        while (!remote_mac_valid && cycles_now() < deadline)
            net_poll();
    }
    return remote_mac_valid ? 0 : -1;
}

const struct net_stats *net_get_stats(void)
{
    stats.rx_dropped_hw = ethmac_sram_writer_errors_read();
    return &stats;
}
