/* hot_text.ld - placement of hot code (included from linker.ld .text).
 *
 * VexRiscv's I-cache is 4 KB and direct-mapped: two functions whose
 * addresses are equal modulo 4 KB evict each other. The ML-DSA signing loop
 * alternates between phases (SHAKE squeezing, NTT/matrix arithmetic, checks);
 * keeping each phase's functions contiguous lets each phase's code fit the
 * cache without self-conflicts. Everything else follows in link order.
 * Requires -ffunction-sections (one .text.<name> section per function). */

/* Phase 1: Keccak-f[1600] and SHAKE absorb/squeeze (~3.8 KB) */
*keccak_pqrv_rv32im.o(.text)
*(.text.BlockSha3)
*(.text.__wrap_BlockSha3)
*(.text.Sha3Update)
*(.text.Sha3Final)
*(.text.InitSha3)
*(.text.wc_Shake256_Update)
*(.text.wc_Shake256_SqueezeBlocks)
*(.text.wc_Shake128_SqueezeBlocks)
*(.text.wc_Shake256_Final)
*(.text.wc_InitShake256)
*(.text.dilithium_shake256*)
*(.text.dilithium_hash256*)

/* Phase 2: ML-DSA polynomial arithmetic and checks */
*(.text.dilithium_decode_gamma1_c*)
*(.text.dilithium_ntt_c*)
*(.text.dilithium_matrix_mul_c*)
*(.text.dilithium_invntt_c*)
*(.text.dilithium_make_pos*)
*(.text.dilithium_vec_make_pos*)
*(.text.dilithium_vec_decompose*)
*(.text.dilithium_decompose_q88*)
*(.text.dilithium_encode_w1_88_c*)
*(.text.dilithium_ntt_small_c*)
*(.text.dilithium_mul_c*)
*(.text.dilithium_sub_c*)
*(.text.dilithium_add_c*)
*(.text.dilithium_check_low*)
*(.text.dilithium_vec_check_low*)
*(.text.dilithium_poly_red*)
*(.text.dilithium_red*)
*(.text.dilithium_vec_add*)
*(.text.__wrap_memcpy)
*(.text.__wrap_memset)
