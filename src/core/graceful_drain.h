/*
 * Graceful Connection Draining for HTTP/2 and HTTP/1.1
 *
 * Manages orderly shutdown of connections during server shutdown:
 * - For HTTP/2: sends GOAWAY frame and waits for client to close
 * - For HTTP/1.1: stops accepting new requests and waits for current to finish
 * - Enforces timeout and force-closes expired connections
 */

#ifndef PQ_CORE_GRACEFUL_DRAIN_H
#define PQ_CORE_GRACEFUL_DRAIN_H

#include <time.h>
#include <stdint.h>
#include <openssl/ssl.h>

typedef struct pq_drain_manager pq_drain_manager_t;

/* Connection being drained */
typedef struct {
    int         fd;            /* Socket file descriptor */
    SSL        *ssl;           /* OpenSSL SSL connection */
    time_t      drain_start;   /* Time when draining began */
    int         h2;            /* Is this HTTP/2? */
    uint32_t    last_stream;   /* Last processed stream ID for HTTP/2 GOAWAY */
} pq_draining_conn_t;

/*
 * Create a new drain manager
 * drain_timeout_sec: seconds to wait before force-closing a draining connection
 * Returns: new drain manager or NULL on error
 */
pq_drain_manager_t* pq_drain_manager_create(int drain_timeout_sec);

/*
 * Destroy drain manager and force-close all connections
 */
void pq_drain_manager_destroy(pq_drain_manager_t *dm);

/*
 * Add a connection to the draining pool
 * For HTTP/2: sends GOAWAY frame
 * For HTTP/1.1: prepares for graceful close
 * Returns: 0 on success, -1 on error (pool full, etc)
 */
int pq_drain_add(pq_drain_manager_t *dm, pq_draining_conn_t *conn);

/*
 * Process draining connections
 * Performs:
 * - Attempts graceful SSL shutdown
 * - Force-closes expired connections (> drain_timeout_sec)
 * - Removes closed connections from pool
 *
 * Returns: number of connections still draining
 */
int pq_drain_tick(pq_drain_manager_t *dm);

/*
 * Force-close all draining connections immediately
 * Used when shutdown cannot wait
 */
void pq_drain_shutdown_all(pq_drain_manager_t *dm);

#endif /* PQ_CORE_GRACEFUL_DRAIN_H */
