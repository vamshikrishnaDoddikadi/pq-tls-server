/*
 * test_http_rewriter.c - Tests for the streaming HTTP/1.x request rewriter
 *
 * Covers header injection on every keep-alive request, removal of spoofed
 * forwarding headers, exact body framing, request-smuggling rejections,
 * Upgrade handling and arbitrary input fragmentation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/proxy/http_rewriter.h"

#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)
#define PASS(name) printf("PASS: %s\n", name)

/* ---- output capture ---- */

typedef struct {
    char   buf[256 * 1024];
    size_t len;
    int    fail_emit;
} sink_t;

static int sink_emit(void *ctx, const void *data, size_t len) {
    sink_t *s = ctx;
    if (s->fail_emit) return -1;
    if (s->len + len >= sizeof(s->buf)) return -1;
    memcpy(s->buf + s->len, data, len);
    s->len += len;
    s->buf[s->len] = '\0';
    return 0;
}

static const char *INJ = "X-Forwarded-For: 203.0.113.7\r\nX-PQ-KEM: X25519MLKEM768\r\n";

static int feed_all(pq_http_rewriter_t *rw, sink_t *s, const char *in) {
    return pq_http_rewriter_feed(rw, (const unsigned char *)in, strlen(in), sink_emit, s);
}

/* Feed one byte at a time: output must be identical to a single feed. */
static int feed_bytewise(pq_http_rewriter_t *rw, sink_t *s, const char *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int rc = pq_http_rewriter_feed(rw, (const unsigned char *)in + i, 1, sink_emit, s);
        if (rc != PQ_RW_OK) return rc;
    }
    return PQ_RW_OK;
}

static int rewrite(const char *in, sink_t *s) {
    memset(s, 0, sizeof(*s));
    pq_http_rewriter_t *rw = pq_http_rewriter_new(INJ);
    ASSERT(rw);
    int rc = feed_all(rw, s, in);
    pq_http_rewriter_free(rw);
    return rc;
}

static int count_occurrences(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)); p += strlen(needle)) n++;
    return n;
}

static sink_t g_a, g_b;

/* ---- tests ---- */

TEST(test_injects_headers) {
    int rc = rewrite("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &g_a);
    ASSERT(rc == PQ_RW_OK);
    ASSERT(strcmp(g_a.buf,
        "GET / HTTP/1.1\r\nHost: a\r\n"
        "X-Forwarded-For: 203.0.113.7\r\nX-PQ-KEM: X25519MLKEM768\r\n\r\n") == 0);
    PASS("test_injects_headers");
}

TEST(test_strips_spoofed_headers) {
    int rc = rewrite("GET / HTTP/1.1\r\nHost: a\r\n"
                     "X-Forwarded-For: 127.0.0.1\r\n"
                     "x-pq-kem: X25519MLKEM768\r\n"
                     "X-Real-IP: 10.0.0.1\r\n"
                     "Forwarded: for=10.0.0.1\r\n"
                     "X_Forwarded_For: 10.9.9.9\r\n"
                     "X-Forwarded-Proto: http\r\n"
                     "Accept: */*\r\n\r\n", &g_a);
    ASSERT(rc == PQ_RW_OK);
    ASSERT(strstr(g_a.buf, "127.0.0.1") == NULL);
    ASSERT(strstr(g_a.buf, "10.0.0.1") == NULL);
    ASSERT(strstr(g_a.buf, "10.9.9.9") == NULL);
    ASSERT(strstr(g_a.buf, "X-Forwarded-Proto: http\r") == NULL);
    ASSERT(count_occurrences(g_a.buf, "X-Forwarded-For:") == 1);
    ASSERT(count_occurrences(g_a.buf, "X-PQ-KEM:") == 1);
    ASSERT(strstr(g_a.buf, "Accept: */*\r\n") != NULL);
    PASS("test_strips_spoofed_headers");
}

TEST(test_keepalive_every_request_rewritten) {
    int rc = rewrite("GET /1 HTTP/1.1\r\nHost: a\r\n\r\n"
                     "GET /2 HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 6.6.6.6\r\n\r\n"
                     "GET /3 HTTP/1.1\r\nHost: a\r\n\r\n", &g_a);
    ASSERT(rc == PQ_RW_OK);
    ASSERT(count_occurrences(g_a.buf, "X-Forwarded-For: 203.0.113.7") == 3);
    ASSERT(strstr(g_a.buf, "6.6.6.6") == NULL);
    PASS("test_keepalive_every_request_rewritten");
}

TEST(test_content_length_body_not_parsed) {
    /* Body looks like a header block; it must be forwarded verbatim. */
    const char *body = "X-Forwarded-For: 1.1.1.1\r\n\r\n";
    char req[512];
    snprintf(req, sizeof(req),
             "POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: %zu\r\n\r\n%s"
             "GET /n HTTP/1.1\r\nHost: a\r\n\r\n", strlen(body), body);
    int rc = rewrite(req, &g_a);
    ASSERT(rc == PQ_RW_OK);
    ASSERT(strstr(g_a.buf, body) != NULL);
    ASSERT(count_occurrences(g_a.buf, "X-Forwarded-For: 203.0.113.7") == 2);
    PASS("test_content_length_body_not_parsed");
}

TEST(test_chunked_body) {
    const char *req =
        "POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1c\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n\r\n"
        "3;ext=1\r\nabc\r\n"
        "0\r\nX-Checksum: 1\r\nX-Real-IP: 8.8.8.8\r\n\r\n"
        "GET /n HTTP/1.1\r\nHost: a\r\n\r\n";
    int rc = rewrite(req, &g_a);
    ASSERT(rc == PQ_RW_OK);
    /* chunk data is opaque */
    ASSERT(strstr(g_a.buf, "1c\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n\r\n") != NULL);
    ASSERT(strstr(g_a.buf, "3;ext=1\r\nabc\r\n") != NULL);
    /* managed header dropped from trailers, others kept */
    ASSERT(strstr(g_a.buf, "X-Checksum: 1\r\n") != NULL);
    ASSERT(strstr(g_a.buf, "8.8.8.8") == NULL);
    ASSERT(count_occurrences(g_a.buf, "X-Forwarded-For: 203.0.113.7") == 2);
    PASS("test_chunked_body");
}

TEST(test_fragmentation_invariance) {
    const char *req =
        "\r\nPOST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n"
        "X-Forwarded-For: 5.5.5.5\r\nConnection: keep-alive, X-Forwarded-For\r\n\r\n"
        "5\r\nhello\r\n0\r\n\r\n"
        "PUT /x HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nbody"
        "GET /y HTTP/1.0\r\n\r\n";
    int rc = rewrite(req, &g_a);
    ASSERT(rc == PQ_RW_OK);

    memset(&g_b, 0, sizeof(g_b));
    pq_http_rewriter_t *rw = pq_http_rewriter_new(INJ);
    rc = feed_bytewise(rw, &g_b, req, strlen(req));
    ASSERT(rc == PQ_RW_OK);
    ASSERT(pq_http_rewriter_request_count(rw) == 3);
    pq_http_rewriter_free(rw);

    ASSERT(g_a.len == g_b.len);
    ASSERT(memcmp(g_a.buf, g_b.buf, g_a.len) == 0);
    ASSERT(strstr(g_a.buf, "Connection: keep-alive\r\n") != NULL);
    ASSERT(strstr(g_a.buf, "5.5.5.5") == NULL);
    PASS("test_fragmentation_invariance");
}

TEST(test_smuggling_rejected) {
    static const char *const bad[] = {
        /* CL + TE */
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        /* conflicting CL */
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        /* whitespace before colon */
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n",
        /* obs-fold */
        "GET / HTTP/1.1\r\nHost: a\r\nX-A: 1\r\n folded\r\n\r\n",
        /* chunked not final */
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        /* chunked twice */
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        /* TE in HTTP/1.0 */
        "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
        /* signed / junk CL */
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5abc\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n",
        /* bare LF line ending */
        "GET / HTTP/1.1\nHost: a\n\n",
        /* bare CR inside a field */
        "GET / HTTP/1.1\r\nHost: a\r\nX-A: 1\r2\r\n\r\n",
        /* missing / duplicate Host in HTTP/1.1 */
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        /* malformed request lines */
        "GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.1 \r\nHost: a\r\n\r\n",
        "GET / HTTP/9.9\r\nHost: a\r\n\r\n",
        /* invalid chunk size / missing CRLF after chunk data */
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n11111111111111111\r\n",
        NULL
    };
    for (int i = 0; bad[i]; i++) {
        int rc = rewrite(bad[i], &g_a);
        if (rc != PQ_RW_BAD_REQUEST) {
            fprintf(stderr, "case %d not rejected (rc=%d): %s\n", i, rc, bad[i]);
        }
        ASSERT(rc == PQ_RW_BAD_REQUEST);
    }
    PASS("test_smuggling_rejected");
}

TEST(test_error_is_sticky) {
    memset(&g_a, 0, sizeof(g_a));
    pq_http_rewriter_t *rw = pq_http_rewriter_new(INJ);
    ASSERT(feed_all(rw, &g_a, "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n") == PQ_RW_BAD_REQUEST);
    ASSERT(feed_all(rw, &g_a, "GET / HTTP/1.1\r\nHost: a\r\n\r\n") == PQ_RW_BAD_REQUEST);
    ASSERT(g_a.len == 0);
    pq_http_rewriter_free(rw);
    PASS("test_error_is_sticky");
}

TEST(test_oversized_head) {
    static char big[PQ_RW_MAX_HEAD + 256];
    int n = snprintf(big, sizeof(big), "GET / HTTP/1.1\r\nHost: a\r\nX-Big: ");
    memset(big + n, 'A', sizeof(big) - (size_t)n - 1);
    big[sizeof(big) - 1] = '\0';
    ASSERT(rewrite(big, &g_a) == PQ_RW_TOO_LARGE);
    PASS("test_oversized_head");
}

TEST(test_binary_protocol_passthrough) {
    const unsigned char tls_like[] = {0x16, 0x03, 0x01, 0x00, 0x05, 'X', '-', 'P', 'Q', 0};
    memset(&g_a, 0, sizeof(g_a));
    pq_http_rewriter_t *rw = pq_http_rewriter_new(INJ);
    ASSERT(pq_http_rewriter_feed(rw, tls_like, sizeof(tls_like), sink_emit, &g_a) == PQ_RW_OK);
    ASSERT(pq_http_rewriter_is_passthrough(rw));
    ASSERT(g_a.len == sizeof(tls_like));
    ASSERT(memcmp(g_a.buf, tls_like, sizeof(tls_like)) == 0);
    pq_http_rewriter_free(rw);

    /* h2c prior knowledge */
    const char *h2 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04";
    size_t h2len = 28;
    memset(&g_a, 0, sizeof(g_a));
    rw = pq_http_rewriter_new(INJ);
    ASSERT(pq_http_rewriter_feed(rw, (const unsigned char *)h2, h2len, sink_emit, &g_a) == PQ_RW_OK);
    ASSERT(pq_http_rewriter_is_passthrough(rw));
    ASSERT(g_a.len == h2len && memcmp(g_a.buf, h2, h2len) == 0);
    pq_http_rewriter_free(rw);
    PASS("test_binary_protocol_passthrough");
}

TEST(test_upgrade_accepted) {
    memset(&g_a, 0, sizeof(g_a));
    pq_http_rewriter_t *rw = pq_http_rewriter_new(INJ);
    ASSERT(feed_all(rw, &g_a, "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n"
                              "Connection: Upgrade\r\n\r\n") == PQ_RW_OK);
    ASSERT(pq_http_rewriter_awaiting_response(rw));
    /* client bytes arriving early are held back */
    size_t before = g_a.len;
    ASSERT(feed_all(rw, &g_a, "\x81\x05hello") == PQ_RW_OK);
    ASSERT(g_a.len == before);
    const char *resp = "HTTP/1.1 101 Switching Protocols\r\n";
    ASSERT(pq_http_rewriter_on_response(rw, (const unsigned char *)resp, strlen(resp),
                                        sink_emit, &g_a) == PQ_RW_OK);
    ASSERT(pq_http_rewriter_is_passthrough(rw));
    ASSERT(g_a.len == before + 7);
    /* frames are relayed verbatim, even if they look like HTTP */
    ASSERT(feed_all(rw, &g_a, "GET / HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n") == PQ_RW_OK);
    ASSERT(strstr(g_a.buf, "X-Forwarded-For: 1.2.3.4") != NULL);
    pq_http_rewriter_free(rw);
    PASS("test_upgrade_accepted");
}

TEST(test_upgrade_refused_resumes_http) {
    memset(&g_a, 0, sizeof(g_a));
    pq_http_rewriter_t *rw = pq_http_rewriter_new(INJ);
    ASSERT(feed_all(rw, &g_a, "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n"
                              "Connection: upgrade\r\n\r\n"
                              "GET /next HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 6.6.6.6\r\n\r\n")
           == PQ_RW_OK);
    ASSERT(pq_http_rewriter_awaiting_response(rw));
    const char *resp = "HTTP/1.1 400 Bad Request\r\n";
    ASSERT(pq_http_rewriter_on_response(rw, (const unsigned char *)resp, 5, sink_emit, &g_a) == PQ_RW_OK);
    ASSERT(pq_http_rewriter_awaiting_response(rw));      /* needs 12 bytes */
    ASSERT(pq_http_rewriter_on_response(rw, (const unsigned char *)resp + 5,
                                        strlen(resp) - 5, sink_emit, &g_a) == PQ_RW_OK);
    ASSERT(!pq_http_rewriter_is_passthrough(rw));
    /* the held-back request was rewritten, not tunnelled */
    ASSERT(strstr(g_a.buf, "6.6.6.6") == NULL);
    ASSERT(count_occurrences(g_a.buf, "X-Forwarded-For: 203.0.113.7") == 2);
    pq_http_rewriter_free(rw);
    PASS("test_upgrade_refused_resumes_http");
}

TEST(test_emit_failure) {
    memset(&g_a, 0, sizeof(g_a));
    g_a.fail_emit = 1;
    pq_http_rewriter_t *rw = pq_http_rewriter_new(INJ);
    ASSERT(feed_all(rw, &g_a, "GET / HTTP/1.1\r\nHost: a\r\n\r\n") == PQ_RW_EMIT_FAILED);
    pq_http_rewriter_free(rw);
    PASS("test_emit_failure");
}

TEST(test_render_forward_headers) {
    char out[PQ_RW_MAX_INJECT];
    int n = pq_http_render_forward_headers(out, sizeof(out), "198.51.100.2",
                                           "X25519MLKEM768", "TLS_AES_256_GCM_SHA384", 1);
    ASSERT(n > 0);
    ASSERT(strstr(out, "X-Forwarded-For: 198.51.100.2\r\n") != NULL);
    ASSERT(strstr(out, "X-Forwarded-Proto: https\r\n") != NULL);
    ASSERT(strstr(out, "X-PQ-KEM: X25519MLKEM768\r\n") != NULL);

    n = pq_http_render_forward_headers(out, sizeof(out), "1.2.3.4\r\nEvil: 1",
                                       "x25519", "C", 0);
    ASSERT(n > 0);
    ASSERT(strstr(out, "\r\nEvil") == NULL);
    ASSERT(strstr(out, "X-PQ-KEM: none\r\n") != NULL);
    ASSERT(pq_http_render_forward_headers(out, 8, "1.2.3.4", "g", "c", 0) == -1);
    PASS("test_render_forward_headers");
}

int run_http_rewriter_tests(void) {
    test_injects_headers();
    test_strips_spoofed_headers();
    test_keepalive_every_request_rewritten();
    test_content_length_body_not_parsed();
    test_chunked_body();
    test_fragmentation_invariance();
    test_smuggling_rejected();
    test_error_is_sticky();
    test_oversized_head();
    test_binary_protocol_passthrough();
    test_upgrade_accepted();
    test_upgrade_refused_resumes_http();
    test_emit_failure();
    test_render_forward_headers();
    return 0;
}
