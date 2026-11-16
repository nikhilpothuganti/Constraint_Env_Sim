/*
 * debug_trap.c - debugging aids (built only with `make DEBUG=1`).
 *
 * 1. Exception catcher. LiteX's trap_entry only dispatches interrupts; on a
 *    CPU exception (misaligned access, illegal instruction...) it returns to
 *    the faulting instruction and the firmware spins silently forever.
 *    debug_trap() replaces mtvec: interrupts still go to LiteX's isr(),
 *    exceptions print mcause/mepc/mtval and halt.
 *
 * 2. Sampling profiler. timer0 fires every `period` cycles and prints the
 *    interrupted PC. Resolve with:
 *        riscv64-unknown-elf-addr2line -f -e boot/boot.elf <pc>
 *
 * Output uses the UART registers directly: with interrupts off (trap
 * context) the buffered LiteX uart_write() silently drops characters.
 */
#include <stdint.h>

#include <irq.h>
#include <generated/csr.h>
#include <generated/soc.h>

#include "debug_trap.h"

void isr(void);    /* LiteX interrupt dispatcher (libbase/isr.c) */

static void raw_putc(char c)
{
    while (uart_txfull_read())
        ;
    uart_rxtx_write(c);
}

static void raw_puts(const char *s)
{
    while (*s)
        raw_putc(*s++);
}

static void raw_hex(uint32_t v)
{
    for (int i = 28; i >= 0; i -= 4)
        raw_putc("0123456789abcdef"[(v >> i) & 0xf]);
}

#define CSR_READ(name) ({ uint32_t v_; __asm__ volatile ("csrr %0, " #name : "=r"(v_)); v_; })

__attribute__((interrupt("machine"), aligned(4)))
static void debug_trap(void)
{
    uint32_t mcause = CSR_READ(mcause);

    if (mcause & 0x80000000u) {          /* interrupt -> normal LiteX path */
        isr();
        return;
    }

    raw_puts("\n\n*** CPU EXCEPTION  mcause=0x");
    raw_hex(mcause);
    raw_puts("  mepc=0x");
    raw_hex(CSR_READ(mepc));
    raw_puts("  mtval=0x");
    raw_hex(CSR_READ(mtval));
    raw_puts(" ***\n(4/6 = misaligned load/store, 2 = illegal instr, 5/7 = access fault)\n");
    for (;;)
        ;
}

#ifdef CSR_TIMER0_BASE
static void profiler_tick(void)
{
    uint32_t pc = CSR_READ(mepc);       /* PC the timer interrupted */
    timer0_ev_pending_write(1);
    raw_puts("[prof] pc=0x");
    raw_hex(pc);
    raw_putc('\n');
}
#endif

void debug_trap_install(uint32_t profile_period_cycles)
{
    __asm__ volatile ("csrw mtvec, %0" :: "r"(debug_trap));

#ifdef CSR_TIMER0_BASE
    if (profile_period_cycles) {
        timer0_en_write(0);
        timer0_load_write(profile_period_cycles);
        timer0_reload_write(profile_period_cycles);
        timer0_ev_pending_write(1);
        timer0_ev_enable_write(1);
        irq_attach(TIMER0_INTERRUPT, profiler_tick);
        irq_setmask(irq_getmask() | (1u << TIMER0_INTERRUPT));
        timer0_en_write(1);
    }
#endif
}
