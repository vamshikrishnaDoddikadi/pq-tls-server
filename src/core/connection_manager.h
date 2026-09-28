/**
 * @file connection_manager.h
 * @brief Multi-client PQ-TLS connection manager
 *
 * Acceptor threads hand each client connection to its own thread (bounded by
 * max_connections), which performs the TLS handshake, enforces the PQ policy
 * and relays traffic to an upstream backend.
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

/** File descriptors of one live connection, so shutdown can unblock it. */
typedef struct {
    int client_fd;
    int backend_fd;
} pq_conn_slot_t;

/* ======================================================================== */
/* Connection manager                                                       */
/* ======================================================================== */

typedef struct {
    /* TLS context (protected by ssl_ctx_lock for hot-reload safety) */
    SSL_CTX          *ssl_ctx;
    pthread_rwlock_t  ssl_ctx_lock;     /* readers: workers, writer: reload */
    void             *oqs_provider;      /* OSSL_PROVIDER* (NULL if not needed/available) */
    void             *default_provider;  /* OSSL_PROVIDER* */
    char              effective_groups[PQ_MAX_GROUPS]; /* groups actually offered (ssl_ctx_lock) */
    atomic_int        pq_available;      /* effective groups include a PQ group */

    /* Listening */
    int               listen_fd;

    /* Configuration. The management API mutates it at runtime: writers hold
     * config_lock exclusively, readers take a snapshot under the read lock. */
    const pq_server_config_t *config;
    pthread_rwlock_t  config_lock;

    /* Acceptor threads */
    pthread_t        *workers;
    int               worker_count;
    pthread_t         health_tid;
    int               health_started;

    /* Per-connection threads */
    pthread_attr_t    conn_attr;
    atomic_int        conn_threads;          /* live connection threads      */
    atomic_int        force_close;           /* drain window expired         */
    pq_conn_slot_t   *slots;
    int              *free_slots;
    int               slot_count;
    int               free_top;
    pthread_mutex_t   slot_lock;

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
    atomic_long       rejected_non_pq;         /* refused by --require-pq */

    /* Rejections */
    atomic_long       rate_limited_connections;
    atomic_long       rejected_overload;       /* max_connections reached */
    atomic_long       bad_requests;            /* 400/408/431 sent by the proxy */

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
 * Rebuild the TLS context from the current configuration (certificates,
 * groups, PQ policy) without dropping connections. Triggered by SIGHUP and
 * by the management API. On failure the previous context stays active.
 *
 * Must NOT be called while holding the config write lock.
 */
int pq_conn_manager_reload(pq_conn_manager_t *mgr);

/**
 * Create and initialize the connection manager.
 * Loads providers, builds the SSL_CTX and binds the listen socket.
 *
 * @return Manager instance or NULL on error.
 */
pq_conn_manager_t* pq_conn_manager_create(const pq_server_config_t *cfg);

/**
 * Start the server — spawns acceptor threads and blocks until
 * pq_conn_manager_stop() is called and in-flight connections have drained
 * (bounded by drain_timeout_ms).
 */
int pq_conn_manager_run(pq_conn_manager_t *mgr);

/**
 * Signal the manager to stop accepting and drain connections.
 * Safe to call from any thread, more than once.
 */
void pq_conn_manager_stop(pq_conn_manager_t *mgr);

/**
 * Free all resources. Call after pq_conn_manager_run() has returned.
 */
void pq_conn_manager_destroy(pq_conn_manager_t *mgr);

/**
 * Write a JSON metrics blob to buf (for health endpoint).
 */
int pq_conn_manager_metrics_json(pq_conn_manager_t *mgr, char *buf, size_t len);

/** Copy the TLS groups currently offered to clients into buf. */
void pq_conn_manager_tls_groups(pq_conn_manager_t *mgr, char *buf, size_t len);

/** Take / release the live-configuration lock (see config_lock). */
void pq_conn_manager_config_rdlock(pq_conn_manager_t *mgr);
void pq_conn_manager_config_wrlock(pq_conn_manager_t *mgr);
void pq_conn_manager_config_unlock(pq_conn_manager_t *mgr);

#endif /* PQ_CONNECTION_MANAGER_H */
