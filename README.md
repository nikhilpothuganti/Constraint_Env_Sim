# PQC DTLS 1.3 on a bare-metal RISC-V IoT device

Inter IIT Tech Meet 14.0, QTrino Labs problem. A post-quantum DTLS 1.3 channel
with **mutual authentication** between a host server and a bare-metal RISC-V
device (VexRiscv, simulated with LiteX + Verilator), using wolfSSL 5.8.4.

| | |
|---|---|
| Protocol | DTLS 1.3 (RFC 9147) only, with a HelloRetryRequest cookie |
| Key exchange | ML-KEM-512 (FIPS 203), the only group offered, no classical fallback |
| Authentication | ML-DSA-44 (FIPS 204) certificates on **both** sides, with a common CA. The device also pins the server certificate (see below) |
| Record protection | TLS_CHACHA20_POLY1305_SHA256 |
| Device | VexRiscv "full" RV32IM, 4 KB direct-mapped I- and D-caches, no OS, picolibc |
| Transport | LiteEth MAC, our own minimal Ethernet/ARP/IPv4/UDP layer (`boot/net.c`) |

Network: device `192.168.1.50:11112` ↔ server `192.168.1.100:11111` over the
simulator's `tap0` interface.

## Results

25 complete sessions back to back on the release firmware
(`results/measure_20261116_155400/`, `scripts/measure.sh 25`). Every session succeeded.

The cycle counts come from the RISC-V `cycle` CSR of the cycle-accurate VexRiscv model.
Milliseconds assume a 100 MHz clock.

| Metric | Median | p90 | Min | Max |
|---|---|---|---|---|
| DTLS 1.3 handshake (`wolfSSL_connect`) | **12.44M cycles = 124 ms** | 15.9M | 10.4M | 35.7M ¹ |
| Full session (context setup + handshake) | **13.89M cycles = 139 ms** | 17.4M | 11.9M | 37.2M |
| of which ML-DSA-44 sign (device CertificateVerify) | 4.43M | 7.75M | 2.80M | 27.4M |
| of which ML-DSA-44 verify (server CertificateVerify) | 2.52M | | | |
| of which ML-KEM-512 keygen + decaps | 0.57M + 0.88M | | | |
| of which waiting on the network | 0.10M | | | |
| Bulk throughput (one-way, 48 × 1400-byte records) | **86 cycles/B = 1.14 MB/s** | | | |
| ROM (`boot.bin`) | **271.5 KB** | | | |
| Peak heap (wolfSSL) | **98.5 KB** (`LOWMEM=1`: ~61 KB) | | | |
| Static RAM (`.data` + `.bss`) / peak stack | 30.6 KB / 2.1 KB | | | |

¹ ML-DSA signing repeats a random number of times (rejection sampling, FIPS 204; 4.25 tries on average for ML-DSA-44). The maximum is a signature that needed about 30 tries. The rest of the handshake is stable at about 8M cycles.

All of this is with **full mutual authentication**:
- The device verifies the server's ML-DSA CertificateVerify and signs its own.
- The server requires and validates the device certificate.
- Certificate validity dates and the hostname are checked.
- Randomness comes from the DRBG.

How the numbers got here, from 64–96M cycles, 424 KB ROM and 744 cycles/byte at first bring-up: every step is logged with measurements in `results/bench_log.txt`.

The decrypted handshake (`results/capture_final/`) shows every message, including the device's Certificate and CertificateVerify. It decrypts with Wireshark/tshark ≥ 4.4 using `sslkeylog.log`:

```bash
tshark -r results/capture_final/dtls.pcap -o tls.keylog_file:results/capture_final/sslkeylog.log -Y dtls
```

In the Wireshark GUI, set *Preferences → Protocols → TLS → (Pre)-Master-Secret log filename* to that `sslkeylog.log`.

## Report and demo

- **Technical report:** `report/report.pdf` (3 pages). The source is `report/report.tex`; build it with `tectonic -X compile report/report.tex`.
- **Demo:** run `scripts/demo.sh [--build]` from macOS. It runs one complete session in the VM and shows four things:
  - the device console, live;
  - the server's view, including `client authenticated`;
  - the cycle counts restated at 100 MHz;
  - the decrypted handshake from the packet capture (needs `brew install wireshark`).

## Repository layout

```
(repository root)                    the provided kit (LiteX, wolfSSL sources, README_kit.md) + our work
  boot/main.c                        entry point
  boot/dtls_client.c                 DTLS 1.3 client: ML-KEM key share, ML-DSA mutual auth, echo + bulk test
  boot/net.c, net.h                  Ethernet/ARP/IPv4/UDP on LiteEth (IRQ-driven RX ring, ARP in ISR)
  boot/wolf_port.c                   platform hooks: time (cycle CSR), RNG seed, gettimeofday
  boot/metrics.c                     heap/stack/wait accounting, per-PQC-op cycle counters (--wrap)
  boot/fastmem.c                     word-wise memcpy/memset (linker --wrap; picolibc is built -Os)
  boot/keccak_pqrv_rv32im.S          Keccak-f[1600], RV32IM assembly from PQRV (TCHES 2025, MIT)
  boot/keccak_pqrv.c                 wolfCrypt BlockSha3() -> PQRV assembly
  boot/keccak_rv32.c                 our generated C Keccak (alternative, KECCAK=rv32)
  boot/pqrv_dilithium_ntt_rv32im.S   ML-DSA NTT/INTT, RV32IM single-issue assembly from PQRV (MIT)
  boot/pqrv_dilithium_zetas.c        its twiddle tables
  boot/hot_text.ld                   placement of hot code for the 4 KB I-cache (included by linker.ld)
  boot/bench.c                       per-primitive microbenchmarks + known-answer tests (BENCH=1)
  boot/debug_trap.c                  trap catcher + PC-sampling profiler (DEBUG/PROFILE builds)
  boot/net_test.c                    UDP echo self-test (NET_SELFTEST)
  boot/wolfssl/wolfcrypt/user_settings.h   wolfSSL configuration (every choice commented)
  boot/certs.h                       generated: CA cert, pinned server cert, device cert + key (DER)
host/dtls_server.c                   host DTLS 1.3 server (native wolfSSL), requires a client cert
patches/                             our two small patches to wolfSSL's dilithium.c (already applied)
certs/mldsa44/                       ML-DSA-44 PKI (CA, server, client)
certs/neg/                           credentials for the negative tests
scripts/                             setup, build, run, test, benchmark, profiling helpers
results/                             saved logs, pcaps and measurement campaigns
```

## Environment

Everything runs in an Ubuntu 24.04 VM. We used OrbStack on macOS, with a
machine named `pqc` and the project folder shared at the same path. Any
Ubuntu 24.04 x86-64/arm64 machine with sudo should work. From macOS, prefix the
commands below with `orb -m pqc`.

### One-time setup

```bash
# 1. Toolchain + LiteX (apt packages, venv ~/litex-env, litex_setup.py, version pins)
bash scripts/setup_vm.sh

# 2. Native wolfSSL for the host server (same 5.8.4 sources as the kit)
git clone --depth 1 -b v5.8.4-stable https://github.com/wolfSSL/wolfssl ~/wolfssl
cd ~/wolfssl && ./autogen.sh && ./configure --prefix=$HOME/wolfssl-native \
    --enable-dtls --enable-dtls13 --enable-dtls-frag-ch --enable-dtls-mtu \
    --enable-mlkem --enable-mldsa --enable-session-ticket --enable-debug \
    --enable-keylog-export CFLAGS=-DKEEP_PEER_CERT && make -j && make install

# 3. OpenSSL >= 3.5 (only to generate the ML-DSA certificates)
cd ~ && wget https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
tar xf openssl-3.5.4.tar.gz && cd openssl-3.5.4 && ./Configure --prefix=$HOME/openssl35 && make -j && make install_sw install_ssldirs

# 4. Certificates (ML-DSA-44; the device key is also written in expanded-only form)
bash scripts/gen_certs.sh 44
bash scripts/gen_neg_certs.sh        # only needed for scripts/verify.sh

# 5. Simulated SoC with Ethernet (once)
bash scripts/sim.sh soc
```

### Deviations from the kit (and why)

| Kit | We use | Reason |
|---|---|---|
| `litex_sim ...` without Ethernet | adds `--with-ethernet --local-ip=192.168.1.50 --remote-ip=192.168.1.100` | the device needs a network for DTLS; the sim creates `tap0` |
| `litex_bare_metal_demo --build-path=build/sim` | `make` in `boot/` (`scripts/sim.sh fw`) | the demo tool ignores compile errors and silently keeps an old `boot.bin` |
| latest `litex_setup.py --init` | picolibc wrapper and lite* cores pinned to LiteX 2025.08 | newer versions no longer build with the bundled LiteX 2025.08 |
| interactive sim | `--non-interactive` when there is no TTY | needed for scripted runs |
| `boot/linker.ld` | one added line: `INCLUDE hot_text.ld` | code placement for the I-cache; memory map unchanged |
| wolfSSL sources | two small patches to `dilithium.c` (`patches/`) | see "wolfSSL patches" below; everything else is configuration in `user_settings.h` |

The CPU, SoC, RAM size and memory map are as provided.

## Build and run

```bash
bash scripts/sim.sh fw          # build firmware -> boot.bin
bash scripts/run_dtls.sh        # server + tcpdump on tap0 + simulator, until the client finishes
```

`run_dtls.sh [timeout_s] [KEM] [mldsa_level]` writes these files to `scripts/out/`:
- `sim_dtls.log`: the device console
- `server.log`
- `dtls.pcap`: the Wireshark capture
- `sslkeylog.log`: the TLS secrets for decrypting the capture

Run only **one** `run_dtls.sh` at a time; it cleans up by process name.
Environment knobs:
- `SERVER_ARGS` (default `-T 10`)
- `NET_RATE` (default `2mbit`, or `none`), described under "Test setup" below

Expected device output (abridged):

```
=== PQC DTLS 1.3 client ===
handshake OK
  version  DTLSv1.3
  cipher   TLS13-CHACHA20-POLY1305-SHA256
  group    ML_KEM_512
  context setup     ... cycles
  handshake         ... cycles
  PQC operations (setup + handshake):
    ML-DSA-44 sign / verify, ML-KEM-512 keygen / decaps: cycles and calls
  [0] sent "hello from RISC-V #0", got "hello from RISC-V #0"
throughput: 67200 B in 48 records, ... cycles/B; server: #GOT 67200 B in 48 records
heap: peak ... B (wolfSSL allocations); stack peak ... B
=== PQC DTLS 1.3 client DONE ===
```

The server prints `client authenticated: CN=riscv-iot-device`.

### Test setup in the simulator

- **Link model (`NET_RATE=2mbit`, `tc netem` on `tap0`).**
  - **The problem:** the simulated PHY delivers frames at one byte per CPU cycle, back to back. The LiteEth MAC has only 2 RX slots, so the third frame of a burst is lost while the ISR copies the first.
  - **Why 2 Mbit/s:** real 100 Mbit/s Ethernet on a 100 MHz core is 8 cycles per byte. The simulator runs about 2M cycles per wall-clock second, so 8 cycles is 4 µs, and 2 Mbit/s on `tap0` is the same link speed in device cycles.
  - **What remains:** occasional losses of small back-to-back frames. The device recovers them with a 50 ms gap ACK (RFC 9147 §7.1, `dtls_client.c`).
- **Server retransmission timer (`-T 10`).** The server runs in real time while the simulated device is ~50× slower than a 100 MHz part. With the default 1 s timer, the server would resend whole flights while the device is still computing.

### Firmware build options

`bash scripts/sim.sh fw VAR=1 ...` (the scripts below always do clean builds):

| Option | Effect |
|---|---|
| `KECCAK=pqrv` (default) / `rv32` / `wolf` | Keccak-f[1600]: PQRV assembly 15.2k cycles, our C 16.1k, wolfCrypt's C 23.1k |
| `NTT=pqrv` (default) / `wolf` | ML-DSA NTT/INTT: PQRV assembly or wolfCrypt's C (signatures byte-identical) |
| `NOPIN=1` | no pinned server certificate: always validate the server's chain against the CA (+1 ML-DSA verify) |
| `LOWMEM=1` | small-memory ML-DSA signing: heap peak ~61 KB instead of ~98 KB, average signature ~2× slower |
| `TRACE=1` | one console line per datagram (cycle stamp, size, record type) |
| `DEBUG=1` | wolfSSL debug log with cycle stamps + trap catcher |
| `PROFILE=1` | PC sampling every `PROFILE_PERIOD` cycles (`scripts/profile.sh`) |
| `BENCH=1` | run the crypto microbenchmarks instead of the client |
| `HEAPDUMP=1` | list live heap blocks when ML-DSA signing starts (the heap peak) |
| `CERT_DIR=...`, `KEY_FILE=...` | embed other device credentials (default `../certs/mldsa44`, relative to `boot/`) |
| `NOCLIENTCERT=1` | test only: present no client certificate |

### Measurement and analysis scripts

| Script | Purpose |
|---|---|
| `scripts/measure.sh [N]` | N complete sessions on the release build, with median/mean/p90/min/max of every metric (`results/measure_*/`) |
| `scripts/bench.sh "<label>" [vars]` | one clean build and one session; appends to `results/bench_log.txt` (the optimisation log) |
| `scripts/run_bench.sh [vars]` | per-primitive microbenchmarks with known-answer tests (no network) |
| `scripts/prof_run.sh`, `scripts/prof_bench.sh` | PC-sampling profiles of the handshake / of ML-DSA signing |
| `scripts/verify.sh [N]` | stability runs and negative tests (below) |

## Design notes

### Server certificate pinning

The device trusts the CA and also holds the server's own certificate
(`wolfSSL_CTX_trust_peer_buffer`). If the server presents exactly that
certificate, wolfSSL skips the CA signature check on it, which saves one
ML-DSA-44 verify (~2.2M cycles).
- The server must still prove possession of its private key with CertificateVerify, which is verified.
- The hostname is still checked.
- Any other certificate goes through full CA validation.

Constrained-device profiles commonly use this pattern (RFC 7925). Build with `NOPIN=1` to disable it.

### wolfSSL patches (`patches/`, already applied to the kit's sources)

1. **`0001-dilithium-sign-cache-padding.patch`.** It adds a configurable gap between the sub-buffers of the ML-DSA signing scratch area.
   - **Why:** all polynomials are 1 KB, and the D-cache is 4 KB direct-mapped, so the rows of A and the polynomials of y mapped to the same lines.
   - **Effect:** −8% average signing time for +320 B of heap. With the gap set to 0 the code is exactly upstream.
2. **`0002-dilithium-pqrv-ntt-hook.patch`.** It routes wolfCrypt's ML-DSA NTT/INTT to the PQRV RV32IM assembly.
   - **Evidence it's identical:** with fixed seeds the signatures are byte-identical to wolfCrypt's C NTT (`BENCH=1` prints a digest of each one).

### Third-party code

- **PQRV** (MIT, `LICENSE-PQRV`): J. Zhang, Y. Yan, J. Huang, Ç. K. Koç, "Optimized Software Implementation of Keccak, Kyber, and Dilithium on RV{32,64}IM{B}{V}", TCHES 2025(1). We use its Keccak-f[1600] and single-issue Dilithium NTT, unmodified. Code: https://github.com/Ji-Peng/PQRV (branch `ches2025`).
- **Interrupts:** both routines use `gp`/`tp` as scratch registers. That's safe here because nothing in the firmware uses them: there's no `__global_pointer$`, so no gp-relative addressing. The Makefile refuses to build an image that defines it.

### wolfSSL 5.8.4 issues found (worked around in `user_settings.h`)

- `WOLFSSL_NO_ML_KEM_1024` breaks ML-KEM-512 group support: in `TLSX_IsGroupSupported` the only `break` sits inside the 1024 block, so `wolfSSL_set_groups` fails with -173. ML-KEM-1024 is kept compiled in.
- DTLS 1.3 (`dtls13.c`) does not build with `NO_AES`. Plain AES is kept compiled in, unused.
- A TLS build with only ML-DSA certificates needs `HAVE_ECC` (`pkCurveOID` guard), so ECC is compiled in but never negotiated.

## Verification

```bash
bash scripts/verify.sh [stability_runs=5]
```

This runs the release firmware N times in a row, then the negative tests.
Each negative test must fail cleanly on both ends, with no session
established and no hang:

| Case | Setup | Expected |
|---|---|---|
| `reject_rogue_ca` | server cert from an untrusted CA, same CN | device rejects the server |
| `reject_wrong_cn` | genuine CA, CN `evil-server` | device rejects (hostname check) |
| `reject_expired` | genuine CA, expired in 2020 | device rejects (validity dates) |
| `rogue_client` | device cert from an untrusted CA | server rejects the device |
| `no_client_cert` | device presents no certificate | server rejects the device |

Latest run on the optimised firmware (`results/verify_20261116_154146/`): **10/10 passed**.

- Device-side rejections: rogue CA `-188` (ASN_NO_SIGNER_E), wrong CN `-322` (DOMAIN_NAME_MISMATCH), expired `-151` (ASN_AFTER_DATE_E).
- Server-side rejections: rogue client `-188`, no client certificate `-345` (NO_PEER_CERT).

Known-answer tests (`BENCH=1`): Keccak-f[1600] on the zero state, SHA3-256("abc"),
SHA-256 (FIPS 180-2 vectors), and ML-DSA sign/verify round trip.

## Known limitations

- **Entropy:** `CustomRngGenerateBlock` (`wolf_port.c`) seeds the DRBG from the cycle counter. The simulated SoC has no TRNG, so this is **not secure** and must be replaced by a hardware entropy source on a real device.
- **Time:** there is no RTC. The device's clock starts at the firmware build time (`FW_EPOCH`), which is used for certificate validity checks.
- **Pinned certificate:** if the server certificate changes, the device falls back to CA validation, which is slower but still works. The pinned copy should be updated with the firmware.
- **Simulator vs hardware:** cycle counts come from the RISC-V `cycle` CSR of the cycle-accurate VexRiscv model. Times in ms assume a 100 MHz clock.
