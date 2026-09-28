/*
 * conn_pool.h - Backend Connection Pool
 *
 * Manages a thread-safe pool of connections to upstream backend servers.
 * Supports up to 16 backends with configurable per-backend and total limits.
 */

#ifndef PQ_CONN_POOL_H
#define PQ_CONN_POOL_H

#include <time.h>

typedef struct pq_conn_pool pq_conn_pool_t;

typedef struct {
    int    fd;
    int    upstream_idx;
    time_t last_used;
    int    in_use;
} pq_pooled_conn_t;

/*
 * Create a new connection pool.
 *
 * max_per_backend: Maximum connections per upstream backend
 * max_total:       Maximum total connections across all backends
 *
 * Returns pool handle, or NULL on error.
 */
pq_conn_pool_t* pq_conn_pool_create(int max_per_backend, int max_total);

/*
 * Destroy the connection pool, closing all connections.
 */
void pq_conn_pool_destroy(pq_conn_pool_t *pool);

/*
 * Acquire an idle connection from the pool.
 *
 * upstream_idx: Index of the backend (0-15)
 *
 * Returns a heap-allocated pooled connection if one is available and
 * reusable, or NULL. A pooled connection is only reusable if it has no
 * pending data and has not been closed by the peer; connections with EOF,
 * errors or unsolicited readable bytes are closed and discarded.
 * The returned connection no longer counts against the pool limits; hand it
 * back with pq_conn_pool_release() or close it with pq_conn_pool_remove().
 */
pq_pooled_conn_t* pq_conn_pool_acquire(pq_conn_pool_t *pool, int upstream_idx);

/*
 * Release a connection back to the pool (takes ownership of conn).
 *
 * Marks the connection as not in_use and updates last_used time. If the
 * per-backend or total idle limit is reached, the connection is closed.
 * conn must be heap-allocated (malloc) and is freed by this call.
 */
void pq_conn_pool_release(pq_conn_pool_t *pool, pq_pooled_conn_t *conn);

/*
 * Close and free a connection obtained from pq_conn_pool_acquire() (or a
 * heap-allocated connection that was never pooled).
 *
 * Used when a connection is detected as broken or should not be reused.
 */
void pq_conn_pool_remove(pq_conn_pool_t *pool, pq_pooled_conn_t *conn);

/*
 * Clean up idle connections older than max_idle_sec.
 *
 * Called periodically (e.g., every 10 seconds) to close stale connections.
 */
void pq_conn_pool_cleanup(pq_conn_pool_t *pool, int max_idle_sec);

/*
 * Get pool statistics.
 *
 * active: (output) number of connections in use
 * idle:   (output) number of idle connections
 */
int pq_conn_pool_stats(const pq_conn_pool_t *pool, int *active, int *idle);

#endif /* PQ_CONN_POOL_H */
