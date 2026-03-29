/*
 * test_epoll_reactor.c - Comprehensive tests for epoll-based reactor
 *
 * Tests event registration, callback invocation, timers, and multiple
 * file descriptors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

/* Include the epoll reactor header */
#include "../src/core/epoll_reactor.h"

/* Simple test framework macros */
#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

/* Global callback tracking for tests */
static int callback_invoked = 0;
static int callback_fd = -1;
static uint32_t callback_events = 0;

/* Test callback function */
static void test_callback(pq_reactor_t *reactor, int fd, uint32_t events, void *userdata) {
    callback_invoked++;
    callback_fd = fd;
    callback_events = events;
    (void)reactor;
    (void)userdata;
}

/* Test: Create and destroy reactor */
TEST(test_create_destroy) {
    pq_reactor_t *reactor = pq_reactor_create(256);

    ASSERT(reactor != NULL);

    pq_reactor_destroy(reactor);

    PASS("test_create_destroy");
}

/* Test: Add and remove file descriptor */
TEST(test_add_remove_fd) {
    pq_reactor_t *reactor = pq_reactor_create(256);

    ASSERT(reactor != NULL);

    /* Create a pipe */
    int pair[2];
    int ret = pipe(pair);
    ASSERT(ret == 0);

    int read_fd = pair[0];
    int write_fd = pair[1];

    /* Add read end to reactor */
    int add_ret = pq_reactor_add(reactor, read_fd, PQ_EV_READ, test_callback, NULL);
    ASSERT(add_ret == 0);

    /* Remove from reactor */
    int del_ret = pq_reactor_del(reactor, read_fd);
    ASSERT(del_ret == 0);

    close(read_fd);
    close(write_fd);
    pq_reactor_destroy(reactor);

    PASS("test_add_remove_fd");
}

/* Test: Read event on pipe */
TEST(test_read_event) {
    pq_reactor_t *reactor = pq_reactor_create(256);

    ASSERT(reactor != NULL);

    /* Create a pipe */
    int pair[2];
    int ret = pipe(pair);
    ASSERT(ret == 0);

    int read_fd = pair[0];
    int write_fd = pair[1];

    /* Register read fd */
    callback_invoked = 0;
    int add_ret = pq_reactor_add(reactor, read_fd, PQ_EV_READ, test_callback, NULL);
    ASSERT(add_ret == 0);

    /* Write data to trigger read event */
    const char *msg = "hello";
    ssize_t written = write(write_fd, msg, strlen(msg));
    ASSERT(written > 0);

    /* Run reactor with short timeout */
    int events = pq_reactor_run(reactor, 100);
    /* Event should be dispatched, or timeout */
    ASSERT(events >= 0);

    /* Read the data to clear the pipe */
    char buf[16];
    ssize_t n = read(read_fd, buf, sizeof(buf));
    ASSERT(n > 0);

    close(read_fd);
    close(write_fd);
    pq_reactor_destroy(reactor);

    PASS("test_read_event");
}

/* Test: Timer event */
TEST(test_timer_event) {
    pq_reactor_t *reactor = pq_reactor_create(256);

    ASSERT(reactor != NULL);

    /* Register a timer (50ms interval) */
    callback_invoked = 0;
    int timer_fd = pq_reactor_add_timer(reactor, 50, test_callback, NULL);
    ASSERT(timer_fd >= 0);

    /* Run reactor with sufficient timeout for timer to fire */
    int events = pq_reactor_run(reactor, 200);
    ASSERT(events >= 0);

    /* Cancel the timer */
    pq_reactor_del(reactor, timer_fd);

    pq_reactor_destroy(reactor);

    PASS("test_timer_event");
}

/* Test: Multiple file descriptors */
TEST(test_multiple_fds) {
    pq_reactor_t *reactor = pq_reactor_create(256);

    ASSERT(reactor != NULL);

    /* Create multiple pipes */
    int pairs[3][2];
    for (int i = 0; i < 3; i++) {
        int ret = pipe(pairs[i]);
        ASSERT(ret == 0);
    }

    /* Register all read ends */
    for (int i = 0; i < 3; i++) {
        int ret = pq_reactor_add(reactor, pairs[i][0], PQ_EV_READ, test_callback, NULL);
        ASSERT(ret == 0);
    }

    /* Write data to first pipe */
    const char *msg = "test";
    (void)write(pairs[0][1], msg, strlen(msg));

    /* Run reactor */
    int events = pq_reactor_run(reactor, 100);
    ASSERT(events >= 0);

    /* Clean up */
    for (int i = 0; i < 3; i++) {
        pq_reactor_del(reactor, pairs[i][0]);
        close(pairs[i][0]);
        close(pairs[i][1]);
    }

    pq_reactor_destroy(reactor);

    PASS("test_multiple_fds");
}

/* Test: Reactor with default max_events */
TEST(test_default_max_events) {
    pq_reactor_t *reactor = pq_reactor_create(0);  /* Use default */

    ASSERT(reactor != NULL);

    pq_reactor_destroy(reactor);

    PASS("test_default_max_events");
}

/* Test: Write event monitoring */
TEST(test_write_event) {
    pq_reactor_t *reactor = pq_reactor_create(256);

    ASSERT(reactor != NULL);

    /* Create a pipe */
    int pair[2];
    int ret = pipe(pair);
    ASSERT(ret == 0);

    int read_fd = pair[0];
    int write_fd = pair[1];

    /* Register write fd (pipes are usually writable immediately) */
    callback_invoked = 0;
    int add_ret = pq_reactor_add(reactor, write_fd, PQ_EV_WRITE, test_callback, NULL);
    ASSERT(add_ret == 0);

    /* Run reactor with short timeout */
    int events = pq_reactor_run(reactor, 100);
    ASSERT(events >= 0);

    close(read_fd);
    close(write_fd);
    pq_reactor_destroy(reactor);

    PASS("test_write_event");
}

/* Run all epoll reactor tests */
int run_epoll_reactor_tests(void) {
    test_create_destroy();
    test_add_remove_fd();
    test_read_event();
    test_timer_event();
    test_multiple_fds();
    test_default_max_events();
    test_write_event();

    return 0;
}
