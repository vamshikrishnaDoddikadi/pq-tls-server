/*
 * test_acl.c - Comprehensive tests for IP-based access control lists
 *
 * Tests allowlist/blocklist modes, CIDR range matching, and IP validation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>

/* Include the ACL header */
#include "../src/security/acl.h"

/* Simple test framework macros */
#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

/* Test: Allowlist mode */
TEST(test_allowlist) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);

    /* Add a CIDR range */
    int ret = pq_acl_add("192.168.1.0/24");
    ASSERT(ret == 0);

    /* IP within range should be allowed */
    int allowed = pq_acl_check("192.168.1.5");
    ASSERT(allowed == 1);

    /* IP outside range should be denied */
    int denied = pq_acl_check("10.0.0.1");
    ASSERT(denied == 0);

    pq_acl_destroy();

    PASS("test_allowlist");
}

/* Test: Blocklist mode */
TEST(test_blocklist) {
    pq_acl_init(PQ_ACL_MODE_BLOCKLIST);

    /* Add a blocked CIDR range */
    int ret = pq_acl_add("10.0.0.0/8");
    ASSERT(ret == 0);

    /* IP in blocked range should be denied */
    int denied = pq_acl_check("10.0.0.1");
    ASSERT(denied == 0);

    /* IP outside blocked range should be allowed */
    int allowed = pq_acl_check("192.168.1.1");
    ASSERT(allowed == 1);

    pq_acl_destroy();

    PASS("test_blocklist");
}

/* Test: Disabled mode (all IPs allowed) */
TEST(test_disabled) {
    pq_acl_init(PQ_ACL_MODE_DISABLED);

    /* All IPs should be allowed */
    int check1 = pq_acl_check("192.168.1.1");
    int check2 = pq_acl_check("10.0.0.1");
    int check3 = pq_acl_check("172.16.0.1");

    ASSERT(check1 == 1);
    ASSERT(check2 == 1);
    ASSERT(check3 == 1);

    pq_acl_destroy();

    PASS("test_disabled");
}

/* Test: Single IP (no CIDR) */
TEST(test_single_ip) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);

    /* Add a single IP */
    int ret = pq_acl_add("192.168.1.42");
    ASSERT(ret == 0);

    /* Exact match should be allowed */
    int allowed = pq_acl_check("192.168.1.42");
    ASSERT(allowed == 1);

    /* Different IP should be denied */
    int denied = pq_acl_check("192.168.1.41");
    ASSERT(denied == 0);

    pq_acl_destroy();

    PASS("test_single_ip");
}

/* Test: Invalid CIDR */
TEST(test_invalid_cidr) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);

    /* Invalid CIDR should return error */
    int ret = pq_acl_add("invalid/cidr/format");
    ASSERT(ret == -1);

    pq_acl_destroy();

    PASS("test_invalid_cidr");
}

/* Test: Multiple CIDR ranges in allowlist */
TEST(test_multiple_ranges) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);

    /* Add multiple ranges */
    int ret1 = pq_acl_add("192.168.0.0/16");
    int ret2 = pq_acl_add("10.0.0.0/8");
    ASSERT(ret1 == 0);
    ASSERT(ret2 == 0);

    /* IPs in either range should be allowed */
    int check1 = pq_acl_check("192.168.1.1");
    int check2 = pq_acl_check("10.5.5.5");

    ASSERT(check1 == 1);
    ASSERT(check2 == 1);

    /* IP outside both ranges should be denied */
    int check3 = pq_acl_check("172.16.0.1");
    ASSERT(check3 == 0);

    pq_acl_destroy();

    PASS("test_multiple_ranges");
}

/* Test: /32 CIDR (single IP as CIDR) */
TEST(test_cidr_32) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);

    /* Add single IP as /32 CIDR */
    int ret = pq_acl_add("203.0.113.1/32");
    ASSERT(ret == 0);

    /* Exact IP should be allowed */
    int allowed = pq_acl_check("203.0.113.1");
    ASSERT(allowed == 1);

    /* Adjacent IP should be denied */
    int denied = pq_acl_check("203.0.113.2");
    ASSERT(denied == 0);

    pq_acl_destroy();

    PASS("test_cidr_32");
}

/* Test: /0 CIDR (all IPs) */
TEST(test_cidr_0) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);

    /* Add /0 (all IPs) */
    int ret = pq_acl_add("0.0.0.0/0");
    ASSERT(ret == 0);

    /* All IPs should be allowed */
    int check1 = pq_acl_check("0.0.0.0");
    int check2 = pq_acl_check("192.168.1.1");
    int check3 = pq_acl_check("255.255.255.255");

    ASSERT(check1 == 1);
    ASSERT(check2 == 1);
    ASSERT(check3 == 1);

    pq_acl_destroy();

    PASS("test_cidr_0");
}

/* Test: Blocklist with multiple ranges */
TEST(test_blocklist_multiple) {
    pq_acl_init(PQ_ACL_MODE_BLOCKLIST);

    /* Block multiple ranges */
    int ret1 = pq_acl_add("10.0.0.0/8");
    int ret2 = pq_acl_add("192.168.0.0/16");
    ASSERT(ret1 == 0);
    ASSERT(ret2 == 0);

    /* IPs in blocked ranges should be denied */
    int check1 = pq_acl_check("10.1.1.1");
    int check2 = pq_acl_check("192.168.1.1");

    ASSERT(check1 == 0);
    ASSERT(check2 == 0);

    /* IPs outside blocked ranges should be allowed */
    int check3 = pq_acl_check("172.16.0.1");
    int check4 = pq_acl_check("203.0.113.1");

    ASSERT(check3 == 1);
    ASSERT(check4 == 1);

    pq_acl_destroy();

    PASS("test_blocklist_multiple");
}

/* ---- Regression tests ------------------------------------------------ */

/* Test: malformed prefixes are rejected ("10.0.0.1/" used to become /0) */
TEST(test_invalid_prefixes) {
    static const char *bad[] = {
        "10.0.0.1/", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/+8",
        "10.0.0.0/ 8", "10.0.0.0/8x", "10.0.0.0/0008", "::/129", "",
        "10.0.0", "1.2.3.4.5", "fe80::1%eth0", "10.0.0.0/8/8",
    };

    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (pq_acl_add(bad[i]) != -1) {
            fprintf(stderr, "accepted invalid entry '%s'\n", bad[i]);
            ASSERT(0);
        }
    }
    ASSERT(pq_acl_add(NULL) == -1);

    /* Nothing was added, so an allowlist denies everything */
    ASSERT(pq_acl_check("10.0.0.1") == 0);
    ASSERT(pq_acl_check("192.0.2.1") == 0);

    /* Over-long entry is rejected, not truncated */
    char longbuf[128];
    memset(longbuf, '0', sizeof(longbuf) - 1);
    longbuf[sizeof(longbuf) - 1] = '\0';
    memcpy(longbuf, "1.2.3.4/", 8);
    ASSERT(pq_acl_add(longbuf) == -1);

    pq_acl_destroy();
    PASS("test_invalid_prefixes");
}

/* Test: IPv6 entries and clients */
TEST(test_ipv6) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);
    ASSERT(pq_acl_add("2001:db8::/32") == 0);
    ASSERT(pq_acl_add("::1") == 0);
    ASSERT(pq_acl_check("2001:db8::1") == 1);
    ASSERT(pq_acl_check("2001:db8:ffff:ffff::1") == 1);
    ASSERT(pq_acl_check("2001:db9::1") == 0);
    ASSERT(pq_acl_check("::1") == 1);
    ASSERT(pq_acl_check("::2") == 0);
    ASSERT(pq_acl_check("10.0.0.1") == 0);
    pq_acl_destroy();

    pq_acl_init(PQ_ACL_MODE_BLOCKLIST);
    ASSERT(pq_acl_add("2001:db8:0:1::/65") == 0);
    ASSERT(pq_acl_check("2001:db8:0:1::5") == 0);
    ASSERT(pq_acl_check("2001:db8:0:1:7fff::5") == 0);
    ASSERT(pq_acl_check("2001:db8:0:1:8000::5") == 1);   /* bit 65 set */
    ASSERT(pq_acl_check("::1") == 1);
    ASSERT(pq_acl_check("192.0.2.1") == 1);
    pq_acl_destroy();

    PASS("test_ipv6");
}

/* Test: IPv4-mapped IPv6 clients match IPv4 rules (dual-stack sockets) */
TEST(test_ipv4_mapped_clients) {
    pq_acl_init(PQ_ACL_MODE_BLOCKLIST);
    ASSERT(pq_acl_add("10.0.0.0/8") == 0);
    ASSERT(pq_acl_check("::ffff:10.1.2.3") == 0);
    ASSERT(pq_acl_check("::ffff:11.1.2.3") == 1);
    pq_acl_destroy();

    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);
    ASSERT(pq_acl_add("10.0.0.0/8") == 0);
    ASSERT(pq_acl_check("::ffff:10.1.2.3") == 1);
    ASSERT(pq_acl_check("10.1.2.3") == 1);
    pq_acl_destroy();

    /* 0.0.0.0/0 covers all IPv4 (incl. mapped) but not native IPv6 */
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);
    ASSERT(pq_acl_add("0.0.0.0/0") == 0);
    ASSERT(pq_acl_check("203.0.113.9") == 1);
    ASSERT(pq_acl_check("::ffff:203.0.113.9") == 1);
    ASSERT(pq_acl_check("2001:db8::1") == 0);
    pq_acl_destroy();

    /* ::/0 covers everything */
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);
    ASSERT(pq_acl_add("::/0") == 0);
    ASSERT(pq_acl_check("203.0.113.9") == 1);
    ASSERT(pq_acl_check("2001:db8::1") == 1);
    pq_acl_destroy();

    PASS("test_ipv4_mapped_clients");
}

/* Test: unparseable client addresses are well-defined */
TEST(test_unparseable_client) {
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);
    ASSERT(pq_acl_add("0.0.0.0/0") == 0);
    ASSERT(pq_acl_check("unknown") == 0);    /* fail closed */
    ASSERT(pq_acl_check(NULL) == 0);
    ASSERT(pq_acl_check("") == 0);
    pq_acl_destroy();

    pq_acl_init(PQ_ACL_MODE_BLOCKLIST);
    ASSERT(pq_acl_add("10.0.0.0/8") == 0);
    ASSERT(pq_acl_check("unknown") == 1);    /* cannot match a blocklist */
    ASSERT(pq_acl_check(NULL) == 1);
    pq_acl_destroy();

    /* Not initialized / destroyed: disabled, everything allowed */
    ASSERT(pq_acl_check("unknown") == 1);
    ASSERT(pq_acl_check("10.0.0.1") == 1);

    PASS("test_unparseable_client");
}

/* Test: pq_acl_replace validates everything before swapping */
TEST(test_acl_replace) {
    static const char good[2][64] = { "10.0.0.0/8", "2001:db8::/32" };
    static const char with_bad[3][64] = { "192.168.0.0/16", "10.0.0.0/99", "1.2.3.4" };
    static const char block[1][64] = { "192.168.0.0/16" };

    ASSERT(pq_acl_replace(PQ_ACL_MODE_ALLOWLIST, good, 2) == 0);
    ASSERT(pq_acl_check("10.1.1.1") == 1);
    ASSERT(pq_acl_check("2001:db8::7") == 1);
    ASSERT(pq_acl_check("192.168.1.1") == 0);

    /* One invalid entry: -1 and the previous ACL is untouched */
    ASSERT(pq_acl_replace(PQ_ACL_MODE_BLOCKLIST, with_bad, 3) == -1);
    ASSERT(pq_acl_check("10.1.1.1") == 1);
    ASSERT(pq_acl_check("192.168.1.1") == 0);

    ASSERT(pq_acl_replace(PQ_ACL_MODE_ALLOWLIST, good, -1) == -1);
    ASSERT(pq_acl_replace(PQ_ACL_MODE_ALLOWLIST, NULL, 1) == -1);
    ASSERT(pq_acl_replace(PQ_ACL_MODE_ALLOWLIST, good, PQ_ACL_MAX_ENTRIES + 1) == -1);
    ASSERT(pq_acl_check("10.1.1.1") == 1);

    /* Switch mode and entries in one step */
    ASSERT(pq_acl_replace(PQ_ACL_MODE_BLOCKLIST, block, 1) == 0);
    ASSERT(pq_acl_check("192.168.1.1") == 0);
    ASSERT(pq_acl_check("10.1.1.1") == 1);

    /* Disable */
    ASSERT(pq_acl_replace(PQ_ACL_MODE_DISABLED, NULL, 0) == 0);
    ASSERT(pq_acl_check("192.168.1.1") == 1);

    /* Legacy API still works after replace */
    pq_acl_init(PQ_ACL_MODE_ALLOWLIST);
    ASSERT(pq_acl_add("172.16.0.0/12") == 0);
    ASSERT(pq_acl_check("172.16.5.5") == 1);
    ASSERT(pq_acl_check("192.168.1.1") == 0);
    pq_acl_destroy();

    PASS("test_acl_replace");
}

/* Concurrent checkers must never observe a partial ACL during replace */
#define ACL_CHECKERS 4
static atomic_int acl_stop;
static atomic_int acl_violations;

static void *acl_checker(void *arg)
{
    (void)arg;
    while (!atomic_load(&acl_stop)) {
        /* In both configurations 10/8 is allowed and 203.0.113/24 denied */
        if (pq_acl_check("10.1.2.3") != 1)
            atomic_fetch_add(&acl_violations, 1);
        if (pq_acl_check("203.0.113.5") != 0)
            atomic_fetch_add(&acl_violations, 1);
    }
    return NULL;
}

TEST(test_acl_replace_concurrent) {
    static const char cfg_a[2][64] = { "10.0.0.0/8", "192.0.2.0/24" };
    static const char cfg_b[3][64] = { "198.51.100.0/24", "10.0.0.0/8", "2001:db8::/32" };

    ASSERT(pq_acl_replace(PQ_ACL_MODE_ALLOWLIST, cfg_a, 2) == 0);
    atomic_store(&acl_stop, 0);
    atomic_store(&acl_violations, 0);

    pthread_t th[ACL_CHECKERS];
    for (int i = 0; i < ACL_CHECKERS; i++)
        ASSERT(pthread_create(&th[i], NULL, acl_checker, NULL) == 0);

    for (int i = 0; i < 5000; i++) {
        if (i & 1)
            ASSERT(pq_acl_replace(PQ_ACL_MODE_ALLOWLIST, cfg_a, 2) == 0);
        else
            ASSERT(pq_acl_replace(PQ_ACL_MODE_ALLOWLIST, cfg_b, 3) == 0);
    }

    atomic_store(&acl_stop, 1);
    for (int i = 0; i < ACL_CHECKERS; i++)
        pthread_join(th[i], NULL);

    ASSERT(atomic_load(&acl_violations) == 0);
    pq_acl_destroy();

    PASS("test_acl_replace_concurrent");
}

/* Run all ACL tests */
int run_acl_tests(void) {
    test_allowlist();
    test_blocklist();
    test_disabled();
    test_single_ip();
    test_invalid_cidr();
    test_multiple_ranges();
    test_cidr_32();
    test_cidr_0();
    test_blocklist_multiple();
    test_invalid_prefixes();
    test_ipv6();
    test_ipv4_mapped_clients();
    test_unparseable_client();
    test_acl_replace();
    test_acl_replace_concurrent();

    return 0;
}
