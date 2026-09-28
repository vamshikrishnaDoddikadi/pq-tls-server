/**
 * @file rate_limiter.c
 * @brief Token bucket rate limiter with per-IP tracking
 * @author Vamshi Krishna Doddikadi
 *
 * Concurrency: all state is protected by one statically initialized mutex
 * that is never destroyed, so init/reinit/destroy may be called while
 * worker threads are inside pq_rate_limiter_allow().
 *
 * Memory is bounded by MAX_TRACKED_IPS. When the table is full, entries
 * whose bucket has fully refilled (and so carry no rate-limiting state) or
 * that have been idle for STALE_SECONDS are evicted; if the table is still
 * full, connections from new IPs are denied (fail closed) and counted.
 * Periodic cleanup is expected from pq_rate_limiter_cleanup() (the health
 * check thread calls it every 10 s); the accept path does no full sweeps
 * except, at most once per second, when the table is full.
 */

#include "rate_limiter.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>

#define MAX_TRACKED_IPS 65536
#define HASH_BUCKETS    16384
#define STALE_SECONDS   300  /* Remove IPs not seen for 5 minutes */
#define FULL_SWEEP_MIN_INTERVAL_SEC 1.0
#define RL_IP_KEY_LEN   64   /* includes NUL; longest IPv6 text is 45 */

typedef struct ip_entry {
    char              ip[RL_IP_KEY_LEN];
    double            tokens;
    struct timespec   last_seen;
    struct ip_entry  *next;
} ip_entry_t;

static pthread_mutex_t rl_lock = PTHREAD_MUTEX_INITIALIZER;

static struct {
    ip_entry_t      *buckets[HASH_BUCKETS];
    int              max_per_sec;
    int              burst;
    int              initialized;
    int              tracked;              /* entries in buckets[] */
    uint64_t         capacity_denials;     /* new IPs denied: table full / OOM */
    struct timespec  last_full_sweep;
    int              swept_once;
} rl;

static inline unsigned int hash_ip(const char *ip) {
    /* FNV-1a hash for good distribution and cache locality */
    unsigned int h = 2166136261U;
    while (*ip) {
        h ^= (unsigned char)*ip;
        h *= 16777619U;
        ip++;
    }
    return h & (HASH_BUCKETS - 1);  /* Faster than % when HASH_BUCKETS is power of 2 */
}

static double time_diff_sec(const struct timespec *a, const struct timespec *b) {
    double d = (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec) / 1e9;
    return (d < 0.0) ? 0.0 : d; /* Clamp to non-negative */
}

/*
 * An entry can be dropped without losing information once its bucket has
 * refilled to the burst size (a fresh entry would look identical), or when
 * it has not been seen for STALE_SECONDS. Caller holds rl_lock.
 */
static int entry_evictable(const ip_entry_t *e, const struct timespec *now) {
    double idle = time_diff_sec(&e->last_seen, now);
    if (idle > STALE_SECONDS)
        return 1;
    return e->tokens + idle * (double)rl.max_per_sec >= (double)rl.burst;
}

/* Remove evictable entries. Caller holds rl_lock. */
static void sweep_locked(const struct timespec *now) {
    for (int i = 0; i < HASH_BUCKETS; i++) {
        ip_entry_t **pp = &rl.buckets[i];
        while (*pp) {
            if (entry_evictable(*pp, now)) {
                ip_entry_t *stale = *pp;
                *pp = stale->next;
                free(stale);
                rl.tracked--;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

static void free_all_locked(void) {
    for (int i = 0; i < HASH_BUCKETS; i++) {
        ip_entry_t *e = rl.buckets[i];
        while (e) {
            ip_entry_t *next = e->next;
            free(e);
            e = next;
        }
        rl.buckets[i] = NULL;
    }
    rl.tracked = 0;
}

void pq_rate_limiter_init(int max_per_sec, int burst) {
    int mps = max_per_sec > 0 ? max_per_sec : 100;
    int b = burst > 0 ? burst : (mps > INT_MAX / 2 ? INT_MAX : mps * 2);

    pthread_mutex_lock(&rl_lock);
    rl.max_per_sec = mps;
    rl.burst = b;

    /* Reconfiguration keeps per-IP state; clamp buckets to the new burst */
    if (rl.initialized) {
        for (int i = 0; i < HASH_BUCKETS; i++) {
            for (ip_entry_t *e = rl.buckets[i]; e; e = e->next) {
                if (e->tokens > (double)b)
                    e->tokens = (double)b;
            }
        }
    }
    rl.initialized = 1;
    pthread_mutex_unlock(&rl_lock);
}

__attribute__((hot))
int pq_rate_limiter_allow(const char *ip) {
    if (__builtin_expect(!ip, 0)) return 1;

    /* Longer strings are not IP addresses and cannot be keyed exactly */
    if (__builtin_expect(strnlen(ip, RL_IP_KEY_LEN) >= RL_IP_KEY_LEN, 0))
        return 0;

    pthread_mutex_lock(&rl_lock);

    if (__builtin_expect(!rl.initialized, 0)) {
        pthread_mutex_unlock(&rl_lock);
        return 1;
    }

    unsigned int idx = hash_ip(ip);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Find or create entry */
    ip_entry_t *entry = rl.buckets[idx];
    while (entry) {
        if (__builtin_expect(strcmp(entry->ip, ip) == 0, 1)) break;
        entry = entry->next;
    }

    if (__builtin_expect(!entry, 0)) {
        if (rl.tracked >= MAX_TRACKED_IPS) {
            /* Table full: reclaim lossless entries, at most once a second */
            if (!rl.swept_once ||
                time_diff_sec(&rl.last_full_sweep, &now) >= FULL_SWEEP_MIN_INTERVAL_SEC) {
                sweep_locked(&now);
                rl.last_full_sweep = now;
                rl.swept_once = 1;
            }
            if (rl.tracked >= MAX_TRACKED_IPS) {
                rl.capacity_denials++;
                pthread_mutex_unlock(&rl_lock);
                return 0;       /* fail closed */
            }
        }

        entry = calloc(1, sizeof(*entry));
        if (__builtin_expect(!entry, 0)) {
            rl.capacity_denials++;
            pthread_mutex_unlock(&rl_lock);
            return 0;           /* fail closed */
        }
        snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
        entry->tokens = (double)rl.burst;
        entry->last_seen = now;
        entry->next = rl.buckets[idx];
        rl.buckets[idx] = entry;
        rl.tracked++;
    }

    /* Refill tokens based on elapsed time */
    double elapsed = time_diff_sec(&entry->last_seen, &now);
    entry->tokens += elapsed * rl.max_per_sec;
    if (__builtin_expect(entry->tokens > rl.burst, 0)) entry->tokens = rl.burst;
    entry->last_seen = now;

    /* Check if we have a token */
    int allowed = 0;
    if (__builtin_expect(entry->tokens >= 1.0, 1)) {
        entry->tokens -= 1.0;
        allowed = 1;
    }

    pthread_mutex_unlock(&rl_lock);
    return allowed;
}

void pq_rate_limiter_cleanup(void) {
    pthread_mutex_lock(&rl_lock);
    if (rl.initialized) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        sweep_locked(&now);
    }
    pthread_mutex_unlock(&rl_lock);
}

void pq_rate_limiter_destroy(void) {
    pthread_mutex_lock(&rl_lock);
    free_all_locked();
    rl.initialized = 0;
    rl.swept_once = 0;
    pthread_mutex_unlock(&rl_lock);
}

void pq_rate_limiter_reinit(int max_per_sec, int burst) {
    if (max_per_sec > 0)
        pq_rate_limiter_init(max_per_sec, burst > 0 ? burst : 0);
    else
        pq_rate_limiter_destroy();
}

int pq_rate_limiter_tracked_ips(void) {
    pthread_mutex_lock(&rl_lock);
    int n = rl.tracked;
    pthread_mutex_unlock(&rl_lock);
    return n;
}

uint64_t pq_rate_limiter_capacity_denials(void) {
    pthread_mutex_lock(&rl_lock);
    uint64_t n = rl.capacity_denials;
    pthread_mutex_unlock(&rl_lock);
    return n;
}
