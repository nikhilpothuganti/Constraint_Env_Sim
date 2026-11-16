/*
 * metrics.h - resource measurement for the report: wolfSSL heap usage
 * (allocator hooks), stack high-water mark (stack painting) and cycles
 * spent blocked on the network (so handshake compute and wait can be
 * reported separately).
 */
#ifndef METRICS_H
#define METRICS_H

#include <stddef.h>
#include <stdint.h>

/* Call first thing in main(): paints the unused stack, hooks wolfSSL's
 * allocator. */
void metrics_init(void);

struct heap_stats {
    size_t cur, peak;          /* bytes requested by wolfSSL, live / max */
    uint32_t allocs, frees;
};
const struct heap_stats *metrics_heap(void);
void metrics_heap_reset_peak(void);   /* peak = cur */

/* Deepest stack use since metrics_init(), in bytes. */
size_t metrics_stack_peak(void);

/* Cycles spent inside the DTLS receive callback waiting for a datagram. */
extern uint64_t metrics_wait_cycles;

/* Cycles inside the PQC operations wolfSSL performs during a handshake,
 * captured with linker --wrap around the wolfCrypt entry points (see
 * Makefile), so the handshake can be broken down per primitive. */
enum { PH_MLDSA_SIGN, PH_MLDSA_VERIFY, PH_MLKEM_KEYGEN, PH_MLKEM_DECAPS, PH_COUNT };
struct phase { uint64_t cycles; uint32_t calls; };
extern struct phase metrics_phase[PH_COUNT];
void metrics_phase_reset(void);
void metrics_phase_print(void);

#endif
