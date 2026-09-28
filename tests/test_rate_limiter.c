/*
 * test_rate_limiter.c - Comprehensive tests for per-IP rate limiter
 *
 * Tests token bucket rate limiting with burst allowance, per-IP tracking,
 * and token refill behavior.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>

/* Include the rate limiter header */
#include "../src/security/rate_limiter.h"

/* Simple test framework macros */
#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

/* Test: Initialize and allow first request */
TEST(test_init_and_allow) {
    pq_rate_limiter_init(10, 5);  /* 10 per sec, burst of 5 */

    int allowed = pq_rate_limiter_allow("192.168.1.1");

    ASSERT(allowed == 1);  /* First request should be allowed */

    pq_rate_limiter_destroy();

    PASS("test_init_and_allow");
}

/* Test: Burst limit enforcement */
TEST(test_burst_limit) {
    int burst = 3;
    pq_rate_limiter_init(100, burst);  /* High rate, small burst */

    /* Allow burst requests */
    for (int i = 0; i < burst; i++) {
        int allowed = pq_rate_limiter_allow("192.168.1.5");
        ASSERT(allowed == 1);
    }

    /* Next request should be denied (burst exhausted) */
    int denied = pq_rate_limiter_allow("192.168.1.5");
    ASSERT(denied == 0);

    pq_rate_limiter_destroy();

    PASS("test_burst_limit");
}

/* Test: Different IPs have independent limits */
TEST(test_different_ips) {
    int burst = 2;
    pq_rate_limiter_init(100, burst);

    /* Exhaust tokens for IP1 */
    pq_rate_limiter_allow("10.0.0.1");
    pq_rate_limiter_allow("10.0.0.1");

    int ip1_denied = pq_rate_limiter_allow("10.0.0.1");
    ASSERT(ip1_denied == 0);

    /* IP2 should still be allowed */
    int ip2_allowed = pq_rate_limiter_allow("10.0.0.2");
    ASSERT(ip2_allowed == 1);

    pq_rate_limiter_destroy();

    PASS("test_different_ips");
}

/* Test: Token refill over time */
TEST(test_token_refill) {
    int max_per_sec = 1;
    int burst = 1;
    pq_rate_limiter_init(max_per_sec, burst);

    const char *ip = "192.168.1.100";

    /* Use the single token */
    int allowed1 = pq_rate_limiter_allow(ip);
    ASSERT(allowed1 == 1);

    /* Next request denied (no tokens) */
    int denied = pq_rate_limiter_allow(ip);
    ASSERT(denied == 0);

    /* Wait for token refill (1+ seconds) */
    struct timespec ts;
    ts.tv_sec = 1;
    ts.tv_nsec = 100000000;  /* 1.1 seconds */
    nanosleep(&ts, NULL);

    /* Request should now be allowed after refill */
    int allowed2 = pq_rate_limiter_allow(ip);
    ASSERT(allowed2 == 1);

    pq_rate_limiter_destroy();

    PASS("test_token_refill");
}

/* Test: Cleanup removes stale entries */
TEST(test_cleanup) {
    pq_rate_limiter_init(10, 5);

    /* Add some entries */
    pq_rate_limiter_allow("192.168.1.1");
    pq_rate_limiter_allow("192.168.1.2");
    pq_rate_limiter_allow("192.168.1.3");

    /* Cleanup should not crash */
    pq_rate_limiter_cleanup();

    /* Limiter should still be functional */
    int allowed = pq_rate_limiter_allow("192.168.1.4");
    ASSERT(allowed == 1);

    pq_rate_limiter_destroy();

    PASS("test_cleanup");
}

/* Test: Same IP exhausts and refills burst independently */
TEST(test_burst_independence) {
    int burst = 2;
    pq_rate_limiter_init(50, burst);

    /* IP1 uses one token */
    pq_rate_limiter_allow("172.16.0.1");

    /* IP1 uses second token */
    pq_rate_limiter_allow("172.16.0.1");

    /* IP1 should now be rate-limited */
    int ip1_limited = pq_rate_limiter_allow("172.16.0.1");
    ASSERT(ip1_limited == 0);

    /* But IP2 should have full burst available */
    int ip2_t1 = pq_rate_limiter_allow("172.16.0.2");
    int ip2_t2 = pq_rate_limiter_allow("172.16.0.2");
    ASSERT(ip2_t1 == 1);
    ASSERT(ip2_t2 == 1);

    pq_rate_limiter_destroy();

    PASS("test_burst_independence");
}

/* Test: High request rate stays limited */
TEST(test_sustained_rate_limit) {
    int max_per_sec = 5;
    int burst = 2;
    pq_rate_limiter_init(max_per_sec, burst);

    const char *ip = "203.0.113.1";

    /* Rapid requests should hit the limit */
    int allowed_count = 0;
    for (int i = 0; i < 20; i++) {
        if (pq_rate_limiter_allow(ip)) {
            allowed_count++;
        }
    }

    /* Should allow burst + maybe a few, but not all 20 */
    ASSERT(allowed_count < 20);
    ASSERT(allowed_count >= burst);  /* At least burst should be allowed */

    pq_rate_limiter_destroy();

    PASS("test_sustained_rate_limit");
}

/* ---- Regression tests ------------------------------------------------ */

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Test: MAX_TRACKED_IPS (65536) is enforced, fail closed, then recovers */
TEST(test_table_capacity_enforced) {
    const int max_tracked = 65536;
    char ip[32];

    /* rate 1/s, burst 5: after one allow() an entry needs 1 s to refill */
    pq_rate_limiter_init(1, 5);
    uint64_t denials_before = pq_rate_limiter_capacity_denials();

    double start = now_sec();
    for (int i = 0; i < max_tracked; i++) {
        snprintf(ip, sizeof(ip), "10.%d.%d.%d", (i >> 16) & 255, (i >> 8) & 255, i & 255);
        ASSERT(pq_rate_limiter_allow(ip) == 1);
    }
    ASSERT(pq_rate_limiter_tracked_ips() == max_tracked);

    /* Nothing is evictable yet (no bucket has refilled): new IP denied */
    int denied = pq_rate_limiter_allow("192.0.2.1");
    double filled_in = now_sec() - start;
    if (filled_in < 0.9) {
        ASSERT(denied == 0);
        ASSERT(pq_rate_limiter_capacity_denials() == denials_before + 1);
        ASSERT(pq_rate_limiter_tracked_ips() == max_tracked);
    } else {
        printf("NOTE: table fill took %.2fs, skipping strict fail-closed check\n", filled_in);
    }

    /* Tracked IPs keep working while the table is full */
    ASSERT(pq_rate_limiter_allow("10.0.0.7") == 1);

    /* Once buckets have refilled, entries are reclaimed and new IPs pass */
    struct timespec ts = { 1, 200 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    ASSERT(pq_rate_limiter_allow("192.0.2.2") == 1);
    ASSERT(pq_rate_limiter_tracked_ips() <= max_tracked);

    /* Periodic cleanup reclaims refilled entries too */
    nanosleep(&ts, NULL);
    pq_rate_limiter_cleanup();
    ASSERT(pq_rate_limiter_tracked_ips() == 0);

    pq_rate_limiter_destroy();
    ASSERT(pq_rate_limiter_tracked_ips() == 0);

    PASS("test_table_capacity_enforced");
}

/* Test: re-init reconfigures in place and keeps per-IP state */
TEST(test_reinit_keeps_state) {
    pq_rate_limiter_init(1, 2);
    ASSERT(pq_rate_limiter_allow("198.51.100.1") == 1);
    ASSERT(pq_rate_limiter_allow("198.51.100.1") == 1);
    ASSERT(pq_rate_limiter_allow("198.51.100.1") == 0);

    /* Reconfiguring must not hand an exhausted client a fresh burst */
    pq_rate_limiter_init(1, 2);
    ASSERT(pq_rate_limiter_allow("198.51.100.1") == 0);

    /* Smaller burst clamps existing buckets */
    ASSERT(pq_rate_limiter_allow("198.51.100.2") == 1);   /* 1 token left */
    pq_rate_limiter_reinit(1, 1);
    ASSERT(pq_rate_limiter_allow("198.51.100.2") == 1);
    ASSERT(pq_rate_limiter_allow("198.51.100.2") == 0);

    /* reinit(0) disables: everything allowed */
    pq_rate_limiter_reinit(0, 0);
    ASSERT(pq_rate_limiter_allow("198.51.100.1") == 1);
    ASSERT(pq_rate_limiter_tracked_ips() == 0);

    /* burst <= 0 defaults to 2x rate (was computed from the raw argument) */
    pq_rate_limiter_init(0, 0);            /* rate 100, burst 200 */
    int ok = 0;
    for (int i = 0; i < 150; i++)
        ok += pq_rate_limiter_allow("198.51.100.3");
    ASSERT(ok == 150);

    /* Over-long keys are not IPs */
    char longip[128];
    memset(longip, '1', sizeof(longip) - 1);
    longip[sizeof(longip) - 1] = '\0';
    ASSERT(pq_rate_limiter_allow(longip) == 0);

    pq_rate_limiter_destroy();
    PASS("test_reinit_keeps_state");
}

/* Test: init/reinit/destroy/cleanup while workers call allow() */
#define RL_WORKERS 4
static atomic_int rl_stop;

static void *rl_worker(void *arg)
{
    int id = *(const int *)arg;
    char ip[32];
    unsigned n = 0;
    while (!atomic_load(&rl_stop)) {
        snprintf(ip, sizeof(ip), "172.16.%d.%u", id, n++ % 200);
        (void)pq_rate_limiter_allow(ip);
    }
    return NULL;
}

TEST(test_concurrent_reconfigure) {
    pq_rate_limiter_init(1000, 2000);
    atomic_store(&rl_stop, 0);

    pthread_t th[RL_WORKERS];
    int ids[RL_WORKERS];
    for (int i = 0; i < RL_WORKERS; i++) {
        ids[i] = i;
        ASSERT(pthread_create(&th[i], NULL, rl_worker, &ids[i]) == 0);
    }

    for (int i = 0; i < 300; i++) {
        switch (i % 4) {
        case 0: pq_rate_limiter_init(100 + i, 0); break;
        case 1: pq_rate_limiter_cleanup(); break;
        case 2: pq_rate_limiter_destroy(); break;
        default: pq_rate_limiter_reinit(50, 60); break;
        }
    }

    atomic_store(&rl_stop, 1);
    for (int i = 0; i < RL_WORKERS; i++)
        pthread_join(th[i], NULL);

    pq_rate_limiter_destroy();
    PASS("test_concurrent_reconfigure");
}

/* Run all rate limiter tests */
int run_rate_limiter_tests(void) {
    test_init_and_allow();
    test_burst_limit();
    test_different_ips();
    test_token_refill();
    test_cleanup();
    test_burst_independence();
    test_sustained_rate_limit();
    test_table_capacity_enforced();
    test_reinit_keeps_state();
    test_concurrent_reconfigure();

    return 0;
}
