#ifndef DEBUG_TRAP_H
#define DEBUG_TRAP_H

#include <stdint.h>

/* Install the exception-reporting trap handler; if profile_period_cycles
 * is non-zero, also print the interrupted PC every that many cycles. */
void debug_trap_install(uint32_t profile_period_cycles);

#endif /* DEBUG_TRAP_H */
