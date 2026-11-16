/*
 * wolf_port.c - platform glue wolfSSL needs on a bare-metal LiteX SoC:
 *   - time:    LowResTimer(), TimeNowInMilliseconds(), gettimeofday()
 *   - entropy: CustomRngGenerateBlock() (seed for the Hash-DRBG)
 */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/internal.h>      /* prototypes for the USER_TICKS hooks */

#include <sys/time.h>
#include <stdint.h>

#include "timing.h"

/* Unix time of the firmware build, passed in by the Makefile. Wall-clock
 * time is this plus uptime: good enough to check certificate validity
 * periods on a device with no RTC (it cannot run backwards before the build). */
#ifndef FW_EPOCH
#error "FW_EPOCH (build time, seconds since 1970) must be defined"
#endif

/* ---------------------------------------------------------------- time */

/* Seconds since boot. Used by wolfSSL for DTLS retransmission timers. */
word32 LowResTimer(void)
{
    return (word32)(cycles_now() / CONFIG_CLOCK_FREQUENCY);
}

#if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
/* Milliseconds since boot. Used by TLS 1.3 ticket age / DTLS 1.3 timers. */
#ifdef WOLFSSL_32BIT_MILLI_TIME
word32 TimeNowInMilliseconds(void)
#else
sword64 TimeNowInMilliseconds(void)
#endif
{
    return millis_now();
}
#endif

int gettimeofday(struct timeval *tv, void *tz);
int gettimeofday(struct timeval *tv, void *tz)
{
    (void)tz;
    if (tv) {
        uint64_t c = cycles_now();
        tv->tv_sec  = (time_t)(FW_EPOCH + c / CONFIG_CLOCK_FREQUENCY);
        tv->tv_usec = (suseconds_t)((c % CONFIG_CLOCK_FREQUENCY) *
                                    1000000ULL / CONFIG_CLOCK_FREQUENCY);
    }
    return 0;
}

/* ------------------------------------------------------------- entropy */

/*
 * PLACEHOLDER - NOT A SECURE ENTROPY SOURCE.
 * The simulated SoC has no TRNG. This mixes the cycle counter (which
 * varies with network timing) through xorshift64*, enough to make
 * ephemeral ML-KEM keys differ between runs during development.
 * Replaced in the entropy work item (TRNG/PRNG integration, see report).
 */
int CustomRngGenerateBlock(unsigned char *output, unsigned int sz)
{
    static uint64_t s;
    s ^= cycles_now() * 0x9E3779B97F4A7C15ULL;
    for (unsigned int i = 0; i < sz; i++) {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        output[i] = (unsigned char)((s * 0x2545F4914F6CDD1DULL) >> 56);
    }
    return 0;
}
