#ifndef DTLS_CLIENT_H
#define DTLS_CLIENT_H

/* Bring up the network, perform the PQC DTLS 1.3 handshake with the
 * server, then exchange `messages` request/reply pairs.
 * Returns 0 on success, -1 on any failure. */
int dtls_client_run(int messages);

#endif /* DTLS_CLIENT_H */
