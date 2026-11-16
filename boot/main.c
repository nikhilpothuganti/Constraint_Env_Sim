/*
 * main.c - firmware entry point for the PQC-DTLS 1.3 RISC-V IoT client.
 *
 * Runs bare-metal on the LiteX VexRiscv SoC (no OS). The BIOS loads this
 * image into main RAM and jumps here.
 *
 * Build with -DNET_SELFTEST to run the UDP echo self-test instead
 * (against scripts/udp_echo.py).
 */
#include <stdio.h>

#include <irq.h>
#include <libbase/uart.h>
#include <generated/csr.h>

#include "debug_trap.h"
#include "dtls_client.h"
#include "net.h"
#include "metrics.h"
#include "bench.h"

#define APP_MESSAGES 3      /* request/reply pairs after the handshake */

int main(void)
{
    metrics_init();
#ifdef CONFIG_CPU_HAS_INTERRUPT
    irq_setmask(0);
    irq_setie(1);
#endif
    uart_init();

#if defined(DTLS_PROFILE)
    debug_trap_install(DTLS_PROFILE);                  /* PC sample every N cycles */
#elif defined(DTLS_DEBUG)
    debug_trap_install(CONFIG_CLOCK_FREQUENCY * 10);   /* PC sample every 10 s */
#endif

#if defined(DTLS_BENCH)
    int rc = bench_run();
#elif defined(NET_SELFTEST)
    int rc = net_echo_test();
#else
    int rc = dtls_client_run(APP_MESSAGES);
#endif

    printf("\nfirmware finished (%s)\n", rc == 0 ? "ok" : "error");
    return rc;
}
