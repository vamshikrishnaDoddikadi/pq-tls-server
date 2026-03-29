/**
 * @file rate_limiter.h
 * @brief Per-IP connection rate limiting using token bucket algorithm
 * @author Vamshi Krishna Doddikadi
 */

#ifndef PQ_RATE_LIMITER_H
#define PQ_RATE_LIMITER_H

#include <stdint.h>

/**
 * Initialize the rate limiter.
 * @param max_per_sec  Maximum new connections per second per IP
 * @param burst        Burst allowance (token bucket capacity)
 */
void pq_rate_limiter_init(int max_per_sec, int burst);

/**
 * Check if a connection from this IP should be allowed.
 * @param ip  Client IP address string (e.g., "192.168.1.1")
 * @return 1 if allowed, 0 if rate-limited
 */
int pq_rate_limiter_allow(const char *ip);

/**
 * Clean up stale entries (call periodically).
 */
void pq_rate_limiter_cleanup(void);

/**
 * Destroy the rate limiter and free all memory.
 */
void pq_rate_limiter_destroy(void);

/**
 * Reinitialize the rate limiter with new parameters at runtime.
 * Destroys the existing instance and creates a new one.
 */
void pq_rate_limiter_reinit(int max_per_sec, int burst);

#endif /* PQ_RATE_LIMITER_H */
