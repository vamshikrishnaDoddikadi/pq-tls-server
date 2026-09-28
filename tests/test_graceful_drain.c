/*
 * test_graceful_drain.c - Tests for graceful connection draining
 *
 * Covers the GOAWAY last-stream-id (client streams are odd) and the drain
 * timeout, which previously never fired because drain_start used the wall
 * clock while pq_drain_tick() compared against CLOCK_MONOTONIC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>

#include "../src/core/graceful_drain.h"
#include "../src/http/h2_frame.h"

#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

static int fd_is_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

/* Read one GOAWAY frame from fd and return its last-stream-id */
static uint32_t read_goaway_last_stream(int fd)
{
    uint8_t buf[H2_FRAME_HEADER_SIZE + 8];
    size_t got = 0;
    while (got < sizeof(buf)) {
        ssize_t n = read(fd, buf + got, sizeof(buf) - got);
        ASSERT(n > 0);
        got += (size_t)n;
    }

    h2_frame_header_t hdr;
    ASSERT(h2_frame_parse_header(buf, sizeof(buf), &hdr) >= 0);
    ASSERT(hdr.type == H2_FRAME_GOAWAY);
    ASSERT(hdr.length == 8);
    ASSERT(hdr.stream_id == 0);

    const uint8_t *p = buf + H2_FRAME_HEADER_SIZE;
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
            (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}

/* Test: odd (client-initiated) last-stream-id is sent unchanged */
TEST(test_goaway_keeps_client_stream_id) {
    static const struct { uint32_t in, out; } cases[] = {
        { 0, 0 }, { 1, 1 }, { 5, 5 }, { 0x7FFFFFFFu, 0x7FFFFFFFu },
        { 0x80000007u, 7 },      /* reserved bit is masked */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pq_drain_manager_t *dm = pq_drain_manager_create(30);
        ASSERT(dm != NULL);

        int sp[2];
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

        pq_draining_conn_t c;
        memset(&c, 0, sizeof(c));
        c.fd = sp[0];
        c.ssl = NULL;
        c.h2 = 1;
        c.last_stream = cases[i].in;
        ASSERT(pq_drain_add(dm, &c) == 0);

        ASSERT(read_goaway_last_stream(sp[1]) == cases[i].out);

        pq_drain_manager_destroy(dm);   /* closes sp[0] */
        close(sp[1]);
    }

    PASS("test_goaway_keeps_client_stream_id");
}

/* Test: connections are force-closed once the drain timeout expires */
TEST(test_drain_timeout_fires) {
    pq_drain_manager_t *dm = pq_drain_manager_create(1);
    ASSERT(dm != NULL);

    int sp[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

    pq_draining_conn_t c;
    memset(&c, 0, sizeof(c));
    c.fd = sp[0];
    c.ssl = NULL;
    c.h2 = 0;
    ASSERT(pq_drain_add(dm, &c) == 0);

    ASSERT(pq_drain_tick(dm) == 1);
    ASSERT(fd_is_open(sp[0]));

    /* Wait past the 1 s timeout (up to 3 s for slow/sanitized runs) */
    int remaining = -1;
    for (int i = 0; i < 30 && remaining != 0; i++) {
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        remaining = pq_drain_tick(dm);
    }
    ASSERT(remaining == 0);
    ASSERT(!fd_is_open(sp[0]));

    pq_drain_manager_destroy(dm);
    close(sp[1]);

    PASS("test_drain_timeout_fires");
}

int run_graceful_drain_tests(void) {
    test_goaway_keeps_client_stream_id();
    test_drain_timeout_fires();
    return 0;
}
