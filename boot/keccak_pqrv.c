/*
 * keccak_pqrv.c - wolfCrypt BlockSha3() on top of the PQRV RV32IM assembly
 * Keccak-f[1600] (keccak_pqrv_rv32im.S). Selected with `make KECCAK=pqrv`.
 *
 * Interrupt safety: the assembly uses gp and tp as scratch registers
 * (saved/restored around the call), so an interrupt taken mid-permutation
 * runs with them clobbered. That is harmless only because nothing in this
 * firmware uses them: the linker script defines no __global_pointer$, so no
 * gp-relative accesses are generated, crt0 never sets gp, and there is no
 * TLS. The Makefile's check-gp target fails the build if that changes.
 */
#include <stdint.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

extern void KeccakF1600_StatePermute_RV32ASM(uint64_t state[25]);
void BlockSha3(word64 *s);

void BlockSha3(word64 *s)
{
    KeccakF1600_StatePermute_RV32ASM((uint64_t *)s);
}
