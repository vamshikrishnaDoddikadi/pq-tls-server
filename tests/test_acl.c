/*
 * test_acl.c - Comprehensive tests for IP-based access control lists
 *
 * Tests allowlist/blocklist modes, CIDR range matching, and IP validation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

    return 0;
}
