/*
 * test_main.c - Main test runner for the Post-Quantum TLS Server test suite
 *
 * Each module exposes `int run_<module>_tests(void)` returning 0 on success
 * (individual assertions abort the process on failure). To add a module,
 * declare its runner below and add one line to the `suites` table.
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
int run_http_rewriter_tests(void);
int run_tls_policy_tests(void);
int run_hpack_tests(void);
int run_graceful_drain_tests(void);
int run_master_worker_tests(void);

typedef struct {
    const char *name;
    int (*run)(void);
} test_suite_t;

static const test_suite_t suites[] = {
    { "HTTP Parser",        run_http_parser_tests },
    { "Connection Pool",    run_conn_pool_tests },
    { "HTTP/2 Frame",       run_h2_frame_tests },
    { "Epoll Reactor",      run_epoll_reactor_tests },
    { "Rate Limiter",       run_rate_limiter_tests },
    { "ACL",                run_acl_tests },
    { "HTTP Rewriter",      run_http_rewriter_tests },
    { "TLS Policy",         run_tls_policy_tests },
    { "HPACK",              run_hpack_tests },
    { "Graceful Drain",     run_graceful_drain_tests },
    { "Master/Worker",      run_master_worker_tests },
};

int main(void) {
    int failed = 0;
    int passed = 0;
    size_t n = sizeof(suites) / sizeof(suites[0]);

    printf("=== Post-Quantum TLS Server Test Suite ===\n\n");

    for (size_t i = 0; i < n; i++) {
        printf("--- %s Tests ---\n", suites[i].name);
        if (suites[i].run() != 0) {
            printf("FAILED: %s tests\n", suites[i].name);
            failed++;
        } else {
            passed++;
        }
        printf("\n");
    }

    printf("=== Test Summary ===\n");
    printf("Suites passed: %d\n", passed);
    printf("Suites failed: %d\n", failed);

    if (failed == 0) {
        printf("\nAll tests passed!\n");
        return 0;
    }
    printf("\nSome tests failed.\n");
    return 1;
}
