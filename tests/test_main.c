/*
 * test_main.c - Main test runner for the Post-Quantum TLS Server test suite
 *
 * Invokes all test modules and provides a summary of results.
 */

#include <stdio.h>
#include <stdlib.h>

/* Forward declarations of test runner functions */
int run_http_parser_tests(void);
int run_conn_pool_tests(void);
int run_h2_frame_tests(void);
int run_epoll_reactor_tests(void);
int run_rate_limiter_tests(void);
int run_acl_tests(void);

int main(void) {
    int failed = 0;
    int passed = 0;

    printf("=== Post-Quantum TLS Server Test Suite ===\n\n");

    /* Run HTTP Parser tests */
    printf("--- HTTP Parser Tests ---\n");
    if (run_http_parser_tests() != 0) {
        printf("FAILED: HTTP Parser tests\n");
        failed++;
    } else {
        passed++;
    }
    printf("\n");

    /* Run Connection Pool tests */
    printf("--- Connection Pool Tests ---\n");
    if (run_conn_pool_tests() != 0) {
        printf("FAILED: Connection Pool tests\n");
        failed++;
    } else {
        passed++;
    }
    printf("\n");

    /* Run HTTP/2 Frame tests */
    printf("--- HTTP/2 Frame Tests ---\n");
    if (run_h2_frame_tests() != 0) {
        printf("FAILED: HTTP/2 Frame tests\n");
        failed++;
    } else {
        passed++;
    }
    printf("\n");

    /* Run Epoll Reactor tests */
    printf("--- Epoll Reactor Tests ---\n");
    if (run_epoll_reactor_tests() != 0) {
        printf("FAILED: Epoll Reactor tests\n");
        failed++;
    } else {
        passed++;
    }
    printf("\n");

    /* Run Rate Limiter tests */
    printf("--- Rate Limiter Tests ---\n");
    if (run_rate_limiter_tests() != 0) {
        printf("FAILED: Rate Limiter tests\n");
        failed++;
    } else {
        passed++;
    }
    printf("\n");

    /* Run ACL tests */
    printf("--- ACL Tests ---\n");
    if (run_acl_tests() != 0) {
        printf("FAILED: ACL tests\n");
        failed++;
    } else {
        passed++;
    }
    printf("\n");

    /* Print summary */
    printf("=== Test Summary ===\n");
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);

    if (failed == 0) {
        printf("\nAll tests passed!\n");
        return 0;
    } else {
        printf("\nSome tests failed.\n");
        return 1;
    }
}
