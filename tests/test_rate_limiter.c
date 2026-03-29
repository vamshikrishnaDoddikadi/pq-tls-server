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

/* Run all rate limiter tests */
int run_rate_limiter_tests(void) {
    test_init_and_allow();
    test_burst_limit();
    test_different_ips();
    test_token_refill();
    test_cleanup();
    test_burst_independence();
    test_sustained_rate_limit();

    return 0;
}
