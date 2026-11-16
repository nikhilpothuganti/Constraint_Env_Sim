/*
 * fastmem.c - word-wise memcpy/memset for the whole firmware.
 *
 * LiteX builds picolibc with -Os, which selects the byte-per-iteration
 * versions of memcpy/memset (PREFER_SIZE_OVER_SPEED in
 * newlib/libc/machine/riscv/memset.S, memcpy.c). Those took ~18% of the
 * handshake (wolfSSL zeroes and copies key/record/polynomial buffers
 * constantly). The link uses `-Wl,--wrap=memcpy,--wrap=memset`, so every
 * call, including libc's internal ones, lands here; libc stays untouched.
 *
 * VexRiscv traps on misaligned accesses, so all word accesses are aligned:
 * a source with a different alignment than the destination is combined
 * from two aligned loads with shifts (little-endian).
 * Built with -fno-tree-loop-distribute-patterns so gcc does not turn these
 * loops back into memcpy/memset calls.
 */
#include <stddef.h>
#include <stdint.h>

void *__wrap_memcpy(void *dst, const void *src, size_t n);
void *__wrap_memset(void *dst, int c, size_t n);

void *__wrap_memset(void *dst, int c, size_t n)
{
    uint8_t *d = dst;
    if (n >= 8) {
        while ((uintptr_t)d & 3) {
            *d++ = (uint8_t)c;
            n--;
        }
        uint32_t w = (uint8_t)c;
        w |= w << 8;
        w |= w << 16;
        uint32_t *dw = (uint32_t *)d;
        for (; n >= 16; n -= 16, dw += 4) {
            dw[0] = w; dw[1] = w; dw[2] = w; dw[3] = w;
        }
        for (; n >= 4; n -= 4)
            *dw++ = w;
        d = (uint8_t *)dw;
    }
    while (n--)
        *d++ = (uint8_t)c;
    return dst;
}

void *__wrap_memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;

    if (n >= 8) {
        while ((uintptr_t)d & 3) {          /* align the destination */
            *d++ = *s++;
            n--;
        }
        uint32_t *dw = (uint32_t *)d;
        unsigned k = (uintptr_t)s & 3;
        if (k == 0) {
            const uint32_t *sw = (const uint32_t *)s;
            for (; n >= 16; n -= 16, dw += 4, sw += 4) {
                uint32_t a = sw[0], b = sw[1], e = sw[2], f = sw[3];
                dw[0] = a; dw[1] = b; dw[2] = e; dw[3] = f;
            }
            for (; n >= 4; n -= 4)
                *dw++ = *sw++;
            s = (const uint8_t *)sw;
        } else {
            /* Source misaligned by k bytes: merge two aligned words. The
             * last aligned load may read up to 3 bytes past the end of the
             * source, never past its last aligned word (harmless here:
             * flat RAM, no MMU). */
            const uint32_t *sw = (const uint32_t *)(s - k);
            unsigned lo = 8 * k, hi = 32 - lo;
            uint32_t w0 = *sw++;
            for (; n >= 4; n -= 4) {
                uint32_t w1 = *sw++;
                *dw++ = (w0 >> lo) | (w1 << hi);
                w0 = w1;
            }
            s = (const uint8_t *)sw - 4 + k;
        }
        d = (uint8_t *)dw;
    }
    while (n--)
        *d++ = *s++;
    return dst;
}
