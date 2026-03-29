/**
 * @file http_proxy.h
 * @brief Bidirectional TCP/HTTP proxy between TLS frontend and upstream backend
 *
 * This module handles:
 *   1. Connecting to an upstream backend (plain TCP).
 *   2. Shuttling data between the SSL* frontend and the raw backend fd
 *      using poll() for efficient bidirectional relay.
 */

#ifndef PQ_HTTP_PROXY_H
#define PQ_HTTP_PROXY_H

#include <openssl/ssl.h>
#include <stddef.h>

typedef struct {
    size_t bytes_from_client;   /* client -> backend */
    size_t bytes_from_backend;  /* backend -> client */
    int    error;               /* 0 = clean close, <0 = error */
} pq_proxy_result_t;

/**
 * Connect to an upstream backend host:port with a timeout.
 *
 * @return socket fd >= 0 on success, -1 on error.
 */
int pq_proxy_connect_upstream(const char *host, uint16_t port, int timeout_ms);

/** PQ/TLS metadata to inject as HTTP headers into the first request */
typedef struct {
    const char *group_name;   /* e.g. "X25519MLKEM768" */
    const char *cipher_name;  /* e.g. "TLS_AES_256_GCM_SHA384" */
    int         is_pq;        /* 1 if post-quantum group was negotiated */
} pq_proxy_info_t;

/**
 * Bidirectional relay between a TLS frontend (ssl) and a plain TCP backend (fd).
 *
 * Reads from client via SSL_read -> writes to backend via send().
 * Reads from backend via recv() -> writes to client via SSL_write.
 *
 * If pq_info is non-NULL, injects X-PQ-KEM, X-PQ-Cipher, and X-PQ-Group
 * headers into the first HTTP request forwarded to the backend.
 *
 * Blocks until either side closes or timeout_ms of inactivity.
 */
pq_proxy_result_t pq_proxy_relay(SSL *ssl, int backend_fd, int timeout_ms,
                                 const pq_proxy_info_t *pq_info);

#endif /* PQ_HTTP_PROXY_H */
