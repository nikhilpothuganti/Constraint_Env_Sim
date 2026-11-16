BUILD_DIR?=../build/

include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

#Wolf includes

SRCS += $(wildcard wolfcrypt/src/*.c)
SRCS += $(wildcard src/*.c)
OBJECTS  = crt0.o main.o net.o net_test.o dtls_client.o wolf_port.o metrics.o fastmem.o
OBJECTS += $(SRCS:.c=.o)
INC  = -I./wolfssl -I./wolfssl/wolfcrypt -I.

all: boot.bin

%.bin: %.elf
	@# PQRV assembly uses gp/tp as scratch (keccak_pqrv.c): refuse images
	@# that rely on the global pointer.
	@! $(TARGET_PREFIX)nm $< | grep -q '__global_pointer\$$' || \
	    { echo "error: __global_pointer$$ defined, PQRV asm would corrupt gp"; exit 1; }
	$(OBJCOPY) -O binary $< $@
ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

vpath %.a $(PACKAGES:%=../%)

# CFLAGS += $(INC) -DWOLFSSL_USER_SETTINGS

CFLAGS += $(INC)
CFLAGS += -DWOLFSSL_USER_SETTINGS

# One section per function/object, so the link's --gc-sections can drop
# every unreferenced function (wolfSSL's unused API, ECC/AES/SHA-1 code
# that is compiled but never called) instead of only whole object files.
CFLAGS += -ffunction-sections -fdata-sections

# Optimisation level. common.mak uses -Os; a later -O option overrides it.
# `make OPT=-O2` etc.
OPT ?=
CFLAGS += $(OPT)

# Per-file speed optimisation for the hot crypto kernels only. Building
# everything with -O2 is SLOWER here: the code grows by ~100 KB and thrashes
# VexRiscv's 4 KB I-cache. `make HOT_OPT=` to disable.
HOT_OPT  ?= -O2
HOT_OBJS ?=
$(HOT_OBJS): CFLAGS += $(HOT_OPT)

# Keccak-f[1600] replacing wolfCrypt's BlockSha3() (-DWOLFSSL_RISCV_ASM on
# sha3.c only removes wolfCrypt's own version). Measured on VexRiscv:
#   KECCAK=pqrv  PQRV RV32IM assembly (TCHES 2025, MIT)    15.2k cycles  [default]
#   KECCAK=rv32  our generated C (scripts/gen_keccak.py)     16.1k cycles
#   KECCAK=wolf  wolfCrypt's generic 64-bit C                23.1k cycles
KECCAK ?= pqrv
ifneq ($(KECCAK),wolf)
LDFLAGS += -Wl,--wrap=BlockSha3        # call counter (metrics.c)
endif
KECCAK_OPT ?= -Os
ifeq ($(KECCAK),pqrv)
# PQRV's RV32IM assembly (TCHES 2025), see keccak_pqrv_rv32im.S.
OBJECTS += keccak_pqrv.o keccak_pqrv_rv32im.o
wolfcrypt/src/sha3.o: CFLAGS += -DWOLFSSL_RISCV_ASM
endif
ifeq ($(KECCAK),rv32)
OBJECTS += keccak_rv32.o
wolfcrypt/src/sha3.o: CFLAGS += -DWOLFSSL_RISCV_ASM
keccak_rv32.o: CFLAGS += $(KECCAK_OPT) -fno-strict-aliasing
endif

# ML-DSA NTT: NTT=pqrv routes wolfCrypt's dilithium NTT/INTT to the PQRV
# RV32IM single-issue assembly (our dilithium.c patch, DILITHIUM_NTT_PQRV).
# NTT=wolf keeps wolfCrypt's C. Fixed-seed signatures are byte-identical either
# way (bench.c prints a digest); avg sign -6%, verify -3%.
NTT ?= pqrv
ifeq ($(NTT),pqrv)
wolfcrypt/src/dilithium.o: CFLAGS += -DDILITHIUM_NTT_PQRV
endif
OBJECTS += pqrv_dilithium_ntt_rv32im.o pqrv_dilithium_zetas.o

# Word-wise memcpy/memset for everything, including libc's own calls
# (fastmem.c; picolibc is built -Os and uses byte loops).
LDFLAGS += -Wl,--wrap=memcpy -Wl,--wrap=memset
# Per-primitive handshake timing (metrics.c): calls from wolfSSL's TLS/ASN
# code into these wolfCrypt functions are timed. Calls inside the defining
# file itself are not redirected (--wrap only affects cross-file calls).
LDFLAGS += -Wl,--wrap=wc_dilithium_sign_ctx_msg -Wl,--wrap=wc_dilithium_verify_ctx_msg \
           -Wl,--wrap=wc_dilithium_verify_msg \
           -Wl,--wrap=wc_MlKemKey_MakeKey -Wl,--wrap=wc_MlKemKey_Decapsulate
fastmem.o: CFLAGS += -O2 -fno-tree-loop-distribute-patterns

# At -Os gcc keeps wolfSSL's tiny rotate helpers (misc.c rotrFixed/rotlFixed,
# 4 instructions) as calls: ~384 calls per SHA-256 block, 8% of the
# handshake. Force inlining of WC_INLINE helpers in these hot files only.
FORCE_INLINE_OBJS ?= wolfcrypt/src/sha256.o
$(FORCE_INLINE_OBJS): CFLAGS += '-DWC_INLINE=inline __attribute__((always_inline))'

# Extra -D options for experiments, e.g. make XDEFS=-DWOLFSSL_SHA3_SMALL
XDEFS ?=
CFLAGS += $(XDEFS)

# `make DEBUG=1`: wolfSSL debug log with cycle timestamps (dtls_client.c).
ifdef DEBUG
dtls_client.o main.o: CFLAGS += -DDTLS_DEBUG
CFLAGS += -DFW_WOLFSSL_DEBUG
OBJECTS += debug_trap.o
endif
# `make PROFILE=1`: exception catcher + PC sampling every PROFILE_PERIOD
# cycles (debug_trap.c), without wolfSSL logging. Histogram with
# scripts/profile.sh.
ifdef PROFILE
PROFILE_PERIOD ?= 200000
main.o: CFLAGS += -DDTLS_PROFILE=$(PROFILE_PERIOD)
ifndef DEBUG
OBJECTS += debug_trap.o
endif
endif
# `make BENCH=1`: crypto microbenchmarks instead of the DTLS client
# (bench.c; scripts/run_bench.sh).
ifdef BENCH
CFLAGS += -DDTLS_BENCH            # global: also keeps ML-DSA keygen in wolfCrypt
OBJECTS += bench.o
ifdef PQRV_NTT
bench.o: CFLAGS += -DBENCH_PQRV_NTT
endif
endif
# `make NOPIN=1`: do not pin the server certificate (always validate the
# server's chain against the CA; one more ML-DSA verify per handshake).
ifdef NOPIN
dtls_client.o: CFLAGS += -DDTLS_NO_PIN
endif
# `make LOWMEM=1`: small-memory ML-DSA signing (user_settings.h FW_LOWMEM).
ifdef LOWMEM
CFLAGS += -DFW_LOWMEM
endif
# `make HEAPDUMP=1`: list live heap blocks when ML-DSA signing starts.
ifdef HEAPDUMP
metrics.o: CFLAGS += -DMETRICS_HEAPDUMP
endif
# `make TRACE=1`: one line per datagram sent/received (dtls_client.c).
ifdef TRACE
dtls_client.o: CFLAGS += -DDTLS_TRACE
endif

# `make NOCLIENTCERT=1`: negative-test build that presents no client
# certificate (the server must reject it). Never for real use.
ifdef NOCLIENTCERT
dtls_client.o: CFLAGS += -DDTLS_NO_CLIENT_CERT
endif

# Build time = the device's notion of "now" at boot (no RTC), used to check
# certificate validity dates. See wolf_port.c.
wolf_port.o: CFLAGS += -DFW_EPOCH=$(shell date +%s)

# Device credentials embedded from certs/ (see scripts/der2c.py).
CERT_DIR ?= ../certs/mldsa44
# Expanded-only ML-DSA private key (gen_certs.sh): OpenSSL's default PKCS#8
# "seed + expanded" form makes wolfSSL re-derive the key from the seed at
# load time (one ML-DSA keygen, ~3.4M cycles); the expanded form loads as is.
KEY_FILE ?= client-key-priv.der
certs.h: $(CERT_DIR)/ca-cert.der $(CERT_DIR)/server-cert.der $(CERT_DIR)/client-cert.der $(CERT_DIR)/$(KEY_FILE)
	python3 ../scripts/der2c.py $(CERT_DIR) $@ $(KEY_FILE)
dtls_client.o: certs.h

boot.elf: $(OBJECTS)
	$(CC) $(LDFLAGS) -T linker.ld -N -o $@ \
		$(OBJECTS) \
		$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
		-Wl,--whole-archive \
		-Wl,--gc-sections \
		-Wl,-Map,$@.map \
		$(LIBS:lib%=-l%)

ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

# pull in dependency info for *existing* .o files
-include $(OBJECTS:.o=.d)

donut.o: CFLAGS   += -w

VPATH = $(BIOS_DIRECTORY):$(BIOS_DIRECTORY)/cmds:$(CPU_DIRECTORY)


%.o: %.cpp
	$(compilexx)

%.o: %.c
	$(compile)

%.o: %.S
	$(assemble)

clean:
	$(RM) $(OBJECTS) boot.elf boot.bin .*~ *~

.PHONY: all clean
