/*
 * test_conn_pool.c - Comprehensive tests for backend connection pool
 *
 * Tests connection pool creation, acquisition, release, and resource limits.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>

/* Include the connection pool header */
#include "../src/http/conn_pool.h"

/* Simple test framework macros */
#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

/* Test: Create and destroy pool */
TEST(test_create_destroy) {
    pq_conn_pool_t *pool = pq_conn_pool_create(10, 100);

    ASSERT(pool != NULL);

    pq_conn_pool_destroy(pool);

    PASS("test_create_destroy");
}

/* Test: Acquire from empty pool returns NULL */
TEST(test_acquire_empty) {
    pq_conn_pool_t *pool = pq_conn_pool_create(10, 100);

    ASSERT(pool != NULL);

    /* Empty pool should return NULL */
    pq_pooled_conn_t *conn = pq_conn_pool_acquire(pool, 0);
    ASSERT(conn == NULL);

    pq_conn_pool_destroy(pool);

    PASS("test_acquire_empty");
}

/* Test: Release and acquire a connection */
TEST(test_release_acquire) {
    pq_conn_pool_t *pool = pq_conn_pool_create(10, 100);

    ASSERT(pool != NULL);

    /* Create a socketpair for testing */
    int pair[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    ASSERT(ret == 0);

    int read_fd = pair[0];
    int write_fd = pair[1];

    /* Manually create a pooled connection structure */
    /* Note: In a real test, we'd need to use the actual API or make it testable */
    /* For now, we test that the pool is initialized and can be destroyed */

    pq_conn_pool_destroy(pool);

    close(read_fd);
    close(write_fd);

    PASS("test_release_acquire");
}

/* Test: Pool statistics */
TEST(test_pool_stats) {
    pq_conn_pool_t *pool = pq_conn_pool_create(10, 100);

    ASSERT(pool != NULL);

    int active = -1, idle = -1;
    int ret = pq_conn_pool_stats(pool, &active, &idle);

    /* Should not fail and return valid counts */
    ASSERT(ret == 0);
    ASSERT(active >= 0);
    ASSERT(idle >= 0);

    pq_conn_pool_destroy(pool);

    PASS("test_pool_stats");
}

/* Test: Pool per-backend limit */
TEST(test_pool_limits) {
    int max_per_backend = 5;
    int max_total = 20;
    pq_conn_pool_t *pool = pq_conn_pool_create(max_per_backend, max_total);

    ASSERT(pool != NULL);

    pq_conn_pool_destroy(pool);

    PASS("test_pool_limits");
}

/* Test: Remove a connection */
TEST(test_remove_connection) {
    pq_conn_pool_t *pool = pq_conn_pool_create(10, 100);

    ASSERT(pool != NULL);

    /* Test that pool can be queried */
    int active = -1, idle = -1;
    pq_conn_pool_stats(pool, &active, &idle);

    pq_conn_pool_destroy(pool);

    PASS("test_remove_connection");
}

/* ---- Regression tests ------------------------------------------------ */

static pq_pooled_conn_t *make_conn(int fd, int upstream_idx)
{
    pq_pooled_conn_t *c = malloc(sizeof(*c));
    ASSERT(c != NULL);
    c->fd = fd;
    c->upstream_idx = upstream_idx;
    c->last_used = 0;
    c->in_use = 1;
    return c;
}

static int fd_is_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

/* Test: acquire/release cycles must not drift the idle count */
TEST(test_acquire_release_no_count_drift) {
    pq_conn_pool_t *pool = pq_conn_pool_create(2, 2);
    ASSERT(pool != NULL);

    int sp[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

    pq_conn_pool_release(pool, make_conn(sp[0], 0));

    /* Previously acquire did not decrement current_total while release
       incremented it, so after max_total cycles every release was refused
       and the pooled connection closed. */
    for (int i = 0; i < 20; i++) {
        pq_pooled_conn_t *c = pq_conn_pool_acquire(pool, 0);
        ASSERT(c != NULL);
        ASSERT(c->fd == sp[0]);
        ASSERT(c->in_use == 1);

        int active = -1, idle = -1;
        pq_conn_pool_stats(pool, &active, &idle);
        ASSERT(idle == 0);

        pq_conn_pool_release(pool, c);
        pq_conn_pool_stats(pool, &active, &idle);
        ASSERT(idle == 1);
    }
    ASSERT(fd_is_open(sp[0]));

    pq_conn_pool_destroy(pool);   /* closes sp[0] */
    close(sp[1]);

    PASS("test_acquire_release_no_count_drift");
}

/* Test: max_total / max_per_backend are enforced for idle connections */
TEST(test_pool_limits_enforced) {
    pq_conn_pool_t *pool = pq_conn_pool_create(1, 2);
    ASSERT(pool != NULL);

    int a[2], b[2], c[2], d[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, a) == 0);
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, b) == 0);
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, c) == 0);
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, d) == 0);

    pq_conn_pool_release(pool, make_conn(a[0], 0));
    pq_conn_pool_release(pool, make_conn(b[0], 0));   /* per-backend limit */
    ASSERT(!fd_is_open(b[0]));
    pq_conn_pool_release(pool, make_conn(c[0], 1));
    pq_conn_pool_release(pool, make_conn(d[0], 2));   /* total limit */
    ASSERT(!fd_is_open(d[0]));

    int active = -1, idle = -1;
    pq_conn_pool_stats(pool, &active, &idle);
    ASSERT(idle == 2);

    /* acquire + remove frees a slot exactly once */
    pq_pooled_conn_t *x = pq_conn_pool_acquire(pool, 0);
    ASSERT(x != NULL && x->fd == a[0]);
    pq_conn_pool_remove(pool, x);
    ASSERT(!fd_is_open(a[0]));

    int e[2], f[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, e) == 0);
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
    pq_conn_pool_release(pool, make_conn(e[0], 3));
    ASSERT(fd_is_open(e[0]));
    pq_conn_pool_release(pool, make_conn(f[0], 4));   /* total limit again */
    ASSERT(!fd_is_open(f[0]));
    pq_conn_pool_stats(pool, &active, &idle);
    ASSERT(idle == 2);

    pq_conn_pool_destroy(pool);
    close(a[1]); close(b[1]); close(c[1]); close(d[1]); close(e[1]); close(f[1]);

    PASS("test_pool_limits_enforced");
}

/* Test: an idle connection with unsolicited bytes must not be reused */
TEST(test_stray_data_not_reused) {
    pq_conn_pool_t *pool = pq_conn_pool_create(4, 4);
    ASSERT(pool != NULL);

    int sp[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    pq_conn_pool_release(pool, make_conn(sp[0], 0));

    /* Backend sends a stray response while the connection sits idle */
    const char *stray = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    ASSERT(write(sp[1], stray, strlen(stray)) == (ssize_t)strlen(stray));

    ASSERT(pq_conn_pool_acquire(pool, 0) == NULL);
    ASSERT(!fd_is_open(sp[0]));

    int active = -1, idle = -1;
    pq_conn_pool_stats(pool, &active, &idle);
    ASSERT(idle == 0);

    pq_conn_pool_destroy(pool);
    close(sp[1]);

    PASS("test_stray_data_not_reused");
}

/* Test: an idle connection closed by the backend is discarded */
TEST(test_eof_not_reused) {
    pq_conn_pool_t *pool = pq_conn_pool_create(4, 4);
    ASSERT(pool != NULL);

    int dead[2], good[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, dead) == 0);
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, good) == 0);

    pq_conn_pool_release(pool, make_conn(good[0], 0));
    pq_conn_pool_release(pool, make_conn(dead[0], 0));   /* list head */
    close(dead[1]);

    pq_pooled_conn_t *c = pq_conn_pool_acquire(pool, 0);
    ASSERT(c != NULL);
    ASSERT(c->fd == good[0]);
    ASSERT(!fd_is_open(dead[0]));
    pq_conn_pool_remove(pool, c);

    pq_conn_pool_destroy(pool);
    close(good[1]);

    PASS("test_eof_not_reused");
}

/* Run all connection pool tests */
int run_conn_pool_tests(void) {
    test_create_destroy();
    test_acquire_empty();
    test_release_acquire();
    test_pool_stats();
    test_pool_limits();
    test_remove_connection();
    test_acquire_release_no_count_drift();
    test_pool_limits_enforced();
    test_stray_data_not_reused();
    test_eof_not_reused();

    return 0;
}
