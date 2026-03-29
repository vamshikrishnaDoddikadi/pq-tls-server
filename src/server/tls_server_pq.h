/**
 * @file tls_server_pq.h
 * @brief Post-Quantum TLS 1.3 Server Header
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 */

#ifndef TLS_SERVER_PQ_H
#define TLS_SERVER_PQ_H

#include <stdint.h>
#include <stdio.h>

/* Opaque server structure */
typedef struct pq_server pq_server_t;

/**
 * Create a new PQ TLS server
 * @param cert_file Path to certificate file
 * @param key_file Path to private key file
 * @param log_file Path to log file (NULL for stderr)
 * @param ca_file Path to CA certificate file for client verification
 * @param require_client_auth Require client certificate verification
 * @param verbose Enable verbose output
 * @return Pointer to server structure or NULL on error
 */
pq_server_t* pq_server_create(const char *cert_file, const char *key_file,
                               const char *log_file, const char *ca_file,
                               int require_client_auth, int verbose);

/**
 * Bind and listen on port
 * @param server Pointer to server structure
 * @param port Port number to listen on
 * @return 0 on success, -1 on error
 */
int pq_server_listen(pq_server_t *server, uint16_t port);

/**
 * Accept client connection
 * @param server Pointer to server structure
 * @return 0 on success, -1 on error
 */
int pq_server_accept(pq_server_t *server);

/**
 * Send data to client
 * @param server Pointer to server structure
 * @param data Data to send
 * @param len Length of data
 * @return Number of bytes sent, -1 on error
 */
int pq_server_send(pq_server_t *server, const uint8_t *data, size_t len);

/**
 * Receive data from client
 * @param server Pointer to server structure
 * @param buf Buffer to receive data into
 * @param buf_len Size of buffer
 * @return Number of bytes received, -1 on error
 */
int pq_server_recv(pq_server_t *server, uint8_t *buf, size_t buf_len);

/**
 * Get performance metrics
 * @param server Pointer to server structure
 * @param duration Output handshake duration in milliseconds
 */
void pq_server_get_metrics(pq_server_t *server, double *duration);

/**
 * Destroy PQ TLS server and free resources
 * @param server Pointer to server structure (can be NULL)
 */
void pq_server_destroy(pq_server_t *server);

#endif /* TLS_SERVER_PQ_H */
