# Host-side DTLS 1.3 server, linked against the native wolfSSL build in the VM.
WOLFSSL_PREFIX ?= $(HOME)/wolfssl-native

CFLAGS  += -O2 -Wall -Wextra -I$(WOLFSSL_PREFIX)/include
LDFLAGS += -L$(WOLFSSL_PREFIX)/lib -Wl,-rpath,$(WOLFSSL_PREFIX)/lib
LDLIBS  += -lwolfssl

dtls_server: dtls_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f dtls_server

.PHONY: clean
