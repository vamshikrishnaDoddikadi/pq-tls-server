/**
 * @file rate_limiter.h
 * @brief Per-IP connection rate limiting using token bucket algorithm
 * @author Vamshi Krishna Doddikadi
 */

#ifndef PQ_RATE_LIMITER_H
#define PQ_RATE_LIMITER_H

#include <stdint.h>

/**
 * Initialize the rate limiter, or reconfigure it at runtime.
 * Safe to call again while other threads call pq_rate_limiter_allow():
 * the parameters are swapped under the lock and per-IP state is kept
 * (buckets are clamped to the new burst). No destroy is needed first.
 * @param max_per_sec  Maximum new connections per second per IP (<=0: 100)
 * @param burst        Burst allowance (token bucket capacity, <=0: 2x rate)
 */
void pq_rate_limiter_init(int max_per_sec, int burst);

/**
 * Check if a connection from this IP should be allowed.
 * At most 65536 IPs are tracked; when the table is full and nothing can
 * be evicted losslessly, new IPs are denied (fail closed) and counted in
 * pq_rate_limiter_capacity_denials(). Already tracked IPs are unaffected.
 * @param ip  Client IP address string (e.g., "192.168.1.1")
 * @return 1 if allowed, 0 if rate-limited
 */
int pq_rate_limiter_allow(const char *ip);

/**
 * Clean up stale entries (call periodically, e.g. every 10 s).
 * The accept path does not sweep the table itself.
 */
void pq_rate_limiter_cleanup(void);

/**
 * Disable the rate limiter and free all per-IP state.
 * Safe to call concurrently with the other functions.
 */
void pq_rate_limiter_destroy(void);

/**
 * Reconfigure at runtime: max_per_sec > 0 is pq_rate_limiter_init()
 * (atomic parameter swap), max_per_sec <= 0 disables the limiter.
 */
void pq_rate_limiter_reinit(int max_per_sec, int burst);

/**
 * Number of IPs currently tracked.
 */
int pq_rate_limiter_tracked_ips(void);

/**
 * Number of connections from untracked IPs denied because the tracking
 * table was full (or memory allocation failed). Cumulative.
 */
uint64_t pq_rate_limiter_capacity_denials(void);

#endif /* PQ_RATE_LIMITER_H */
