/*
 * timing.h - cycle-accurate time base for the bare-metal RISC-V firmware.
 *
 * Uses the RISC-V `cycle` CSR (64-bit, read as two 32-bit halves on RV32).
 * The cycle counter is also how performance (handshake, KEM, signatures)
 * is reported: cycles are exact in simulation, whereas wall-clock time
 * depends on how fast Verilator happens to run on the host.
 */
#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>
#include <generated/soc.h>   /* CONFIG_CLOCK_FREQUENCY */

static inline uint64_t cycles_now(void)
{
    uint32_t hi, lo, hi2;
    /* Re-read if the low word wrapped between the two high-word reads. */
    do {
        __asm__ volatile ("csrr %0, cycleh" : "=r"(hi));
        __asm__ volatile ("csrr %0, cycle"  : "=r"(lo));
        __asm__ volatile ("csrr %0, cycleh" : "=r"(hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

/* Simulated time derived from the SoC clock frequency. */
static inline uint64_t millis_now(void)
{
    return cycles_now() / (CONFIG_CLOCK_FREQUENCY / 1000);
}

#endif /* TIMING_H */
