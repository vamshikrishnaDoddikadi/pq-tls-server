/**
 * @file rate_limiter.c
 * @brief Token bucket rate limiter with per-IP tracking
 * @author Vamshi Krishna Doddikadi
 */

#include "rate_limiter.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define MAX_TRACKED_IPS 65536
#define HASH_BUCKETS    4096
#define STALE_SECONDS   300  /* Remove IPs not seen for 5 minutes */

typedef struct ip_entry {
    char              ip[64];
    double            tokens;
    struct timespec   last_seen;
    struct ip_entry  *next;
} ip_entry_t;

static struct {
    ip_entry_t     *buckets[HASH_BUCKETS];
    pthread_mutex_t  mutex;
    int              max_per_sec;
    int              burst;
    int              initialized;
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

static double time_diff_sec(struct timespec *a, struct timespec *b) {
    double d = (b->tv_sec - a->tv_sec) + (b->tv_nsec - a->tv_nsec) / 1e9;
    return (d < 0.0) ? 0.0 : d; /* Clamp to non-negative */
}

void pq_rate_limiter_init(int max_per_sec, int burst) {
    memset(&rl, 0, sizeof(rl));
    pthread_mutex_init(&rl.mutex, NULL);
    rl.max_per_sec = max_per_sec > 0 ? max_per_sec : 100;
    rl.burst = burst > 0 ? burst : max_per_sec * 2;
    rl.initialized = 1;
}

__attribute__((hot))
int pq_rate_limiter_allow(const char *ip) {
    if (__builtin_expect(!rl.initialized || !ip, 0)) return 1;

    pthread_mutex_lock(&rl.mutex);

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
        entry = calloc(1, sizeof(*entry));
        if (__builtin_expect(!entry, 0)) { pthread_mutex_unlock(&rl.mutex); return 1; }
        strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
        entry->tokens = (double)rl.burst;
        entry->last_seen = now;
        entry->next = rl.buckets[idx];
        rl.buckets[idx] = entry;
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

    pthread_mutex_unlock(&rl.mutex);
    return allowed;
}

void pq_rate_limiter_cleanup(void) {
    if (__builtin_expect(!rl.initialized, 0)) return;

    pthread_mutex_lock(&rl.mutex);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (int i = 0; i < HASH_BUCKETS; i++) {
        ip_entry_t **pp = &rl.buckets[i];
        while (*pp) {
            if (__builtin_expect(time_diff_sec(&(*pp)->last_seen, &now) > STALE_SECONDS, 0)) {
                ip_entry_t *stale = *pp;
                *pp = stale->next;
                free(stale);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    pthread_mutex_unlock(&rl.mutex);
}

void pq_rate_limiter_destroy(void) {
    if (!rl.initialized) return;

    pthread_mutex_lock(&rl.mutex);
    for (int i = 0; i < HASH_BUCKETS; i++) {
        ip_entry_t *e = rl.buckets[i];
        while (e) {
            ip_entry_t *next = e->next;
            free(e);
            e = next;
        }
        rl.buckets[i] = NULL;
    }
    pthread_mutex_unlock(&rl.mutex);
    pthread_mutex_destroy(&rl.mutex);
    rl.initialized = 0;
}

void pq_rate_limiter_reinit(int max_per_sec, int burst) {
    pq_rate_limiter_destroy();
    if (max_per_sec > 0) {
        pq_rate_limiter_init(max_per_sec, burst > 0 ? burst : max_per_sec * 2);
    }
}
