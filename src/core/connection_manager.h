/**
 * @file connection_manager.h
 * @brief Multi-client connection manager using epoll + thread pool
 *
 * Manages PQ-TLS frontend connections and proxies traffic to upstream
 * backends using a fixed thread pool.
 */

#ifndef PQ_CONNECTION_MANAGER_H
#define PQ_CONNECTION_MANAGER_H

#include "server_config.h"
#include "../common/crypto_registry.h"
#include <openssl/ssl.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

/* ======================================================================== */
/* Connection state                                                         */
/* ======================================================================== */

typedef enum {
    CONN_STATE_ACCEPTING,
    CONN_STATE_TLS_HANDSHAKE,
    CONN_STATE_ACTIVE,
    CONN_STATE_DRAINING,
    CONN_STATE_CLOSED
} pq_conn_state_t;

typedef struct pq_connection {
    int               client_fd;
    int               backend_fd;
    SSL              *ssl;
    pq_conn_state_t   state;
    struct timespec    connected_at;
    char              client_addr[64];
    uint16_t          client_port;
    size_t            bytes_in;
    size_t            bytes_out;
    int               upstream_idx;     /* which upstream backend */
} pq_connection_t;

/* ======================================================================== */
/* Connection manager                                                       */
/* ======================================================================== */

typedef struct {
    /* TLS context (protected by ssl_ctx_lock for hot-reload safety) */
    SSL_CTX          *ssl_ctx;
    pthread_rwlock_t  ssl_ctx_lock;     /* readers: workers, writer: reload */
    void             *oqs_provider;      /* OSSL_PROVIDER* */
    void             *default_provider;  /* OSSL_PROVIDER* */

    /* Listening */
    int               listen_fd;

    /* Configuration */
    const pq_server_config_t *config;

    /* Thread pool */
    pthread_t        *workers;
    int               worker_count;

    /* State */
    atomic_int        running;
    atomic_long       total_connections;
    atomic_int        active_connections;
    atomic_long       total_bytes_in;
    atomic_long       total_bytes_out;
    atomic_long       total_handshake_failures;

    /* PQ negotiation tracking */
    atomic_long       pq_negotiations;        /* ML-KEM based exchanges */
    atomic_long       classical_negotiations;  /* X25519/P-256 only */

    /* Rate limiting stats */
    atomic_long       rate_limited_connections;

    /* Per-instance upstream health (avoids global state) */
    atomic_int        upstream_healthy[PQ_MAX_UPSTREAMS];

    /* Management UI state */
    atomic_int        restart_pending;          /* 0=none, 1=pending, 2=restart now */
    time_t            start_time;               /* Server start timestamp */

    /* Logging */
    FILE             *log_fp;
    pthread_mutex_t   log_mutex;
    int               json_logging;           /* structured JSON logs */

    /* Crypto-agility registry */
    pq_registry_t    *crypto_registry;        /* algorithm registry (NULL if not initialized) */
} pq_conn_manager_t;

/**
 * Reload TLS certificates and configuration without dropping connections.
 * Triggered by SIGHUP.
 */
int pq_conn_manager_reload(pq_conn_manager_t *mgr);

/**
 * Create and initialize the connection manager.
 * Sets up SSL_CTX, loads OQS provider, binds listen socket.
 *
 * @return Manager instance or NULL on error.
 */
pq_conn_manager_t* pq_conn_manager_create(const pq_server_config_t *cfg);

/**
 * Start the server — spawns worker threads and enters the accept loop.
 * Blocks until pq_conn_manager_stop() is called.
 */
int pq_conn_manager_run(pq_conn_manager_t *mgr);

/**
 * Signal the manager to stop accepting and drain connections.
 */
void pq_conn_manager_stop(pq_conn_manager_t *mgr);

/**
 * Free all resources.
 */
void pq_conn_manager_destroy(pq_conn_manager_t *mgr);

/**
 * Write a JSON metrics blob to buf (for health endpoint).
 */
int pq_conn_manager_metrics_json(const pq_conn_manager_t *mgr, char *buf, size_t len);

#endif /* PQ_CONNECTION_MANAGER_H */
