/*
 * test_http_parser.c - Comprehensive tests for HTTP/1.1 parser
 *
 * Tests the incremental parsing of HTTP requests including headers,
 * methods, URIs, and edge cases.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Include the HTTP parser header */
#include "../src/http/http_parser.h"

/* Simple test framework macros */
#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

/* Test: Parse a simple GET request */
TEST(test_simple_get) {
    pq_http_request_t req;
    const char *data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t consumed = 0;

    pq_http_request_init(&req);

    pq_http_parse_status_t status = pq_http_request_parse(&req, data, strlen(data), &consumed);

    ASSERT(status == HTTP_PARSE_COMPLETE);
    ASSERT(req.method == HTTP_METHOD_GET);
    ASSERT(strcmp(req.uri, "/") == 0);
    ASSERT(req.version_major == 1);
    ASSERT(req.version_minor == 1);
    ASSERT(req.header_count == 1);

    const char *host = pq_http_request_get_header(&req, "Host");
    ASSERT(host != NULL);
    ASSERT(strcmp(host, "example.com") == 0);

    ASSERT(req.keep_alive == 1);  /* HTTP/1.1 defaults to keep-alive */

    PASS("test_simple_get");
}

/* Test: Parse POST with Content-Length */
TEST(test_post_with_content_length) {
    pq_http_request_t req;
    const char *data = "POST /api/submit HTTP/1.1\r\n"
                       "Host: api.example.com\r\n"
                       "Content-Length: 42\r\n\r\n";
    size_t consumed = 0;

    pq_http_request_init(&req);

    pq_http_parse_status_t status = pq_http_request_parse(&req, data, strlen(data), &consumed);

    ASSERT(status == HTTP_PARSE_COMPLETE);
    ASSERT(req.method == HTTP_METHOD_POST);
    ASSERT(strcmp(req.uri, "/api/submit") == 0);
    ASSERT(req.content_length == 42);
    ASSERT(req.chunked == 0);

    PASS("test_post_with_content_length");
}

/* Test: Parse request with Transfer-Encoding: chunked */
TEST(test_chunked_transfer) {
    pq_http_request_t req;
    const char *data = "POST /upload HTTP/1.1\r\n"
                       "Host: example.com\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n";
    size_t consumed = 0;

    pq_http_request_init(&req);

    pq_http_parse_status_t status = pq_http_request_parse(&req, data, strlen(data), &consumed);

    ASSERT(status == HTTP_PARSE_COMPLETE);
    ASSERT(req.method == HTTP_METHOD_POST);
    ASSERT(req.chunked == 1);
    ASSERT(req.content_length == -1);

    PASS("test_chunked_transfer");
}

/* Test: Keep-alive detection (HTTP/1.1 default, HTTP/1.0 explicit) */
TEST(test_keep_alive_detection) {
    pq_http_request_t req;
    size_t consumed = 0;

    /* HTTP/1.1 defaults to keep-alive */
    pq_http_request_init(&req);
    const char *data_11 = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    pq_http_request_parse(&req, data_11, strlen(data_11), &consumed);
    ASSERT(req.keep_alive == 1);

    /* HTTP/1.0 defaults to close */
    pq_http_request_init(&req);
    const char *data_10 = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    pq_http_request_parse(&req, data_10, strlen(data_10), &consumed);
    ASSERT(req.keep_alive == 0);

    /* Connection: close overrides HTTP/1.1 keep-alive default */
    pq_http_request_init(&req);
    const char *data_close = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    pq_http_request_parse(&req, data_close, strlen(data_close), &consumed);
    ASSERT(req.keep_alive == 0);

    PASS("test_keep_alive_detection");
}

/* Test: Incremental parsing (byte-by-byte) */
TEST(test_incremental_parse) {
    pq_http_request_t req;
    const char *data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t total_len = strlen(data);

    pq_http_request_init(&req);

    /* Feed data one byte at a time */
    for (size_t i = 0; i < total_len - 1; i++) {
        size_t consumed = 0;
        pq_http_parse_status_t status = pq_http_request_parse(&req, data + i, 1, &consumed);
        ASSERT(status == HTTP_PARSE_INCOMPLETE || status == HTTP_PARSE_COMPLETE);
        if (status == HTTP_PARSE_COMPLETE) {
            break;
        }
    }

    /* Final byte should complete the parse */
    size_t consumed = 0;
    pq_http_parse_status_t status = pq_http_request_parse(&req, data + total_len - 1, 1, &consumed);
    ASSERT(status == HTTP_PARSE_COMPLETE);
    ASSERT(req.method == HTTP_METHOD_GET);

    PASS("test_incremental_parse");
}

/* Test: Parse request with multiple headers */
TEST(test_multiple_headers) {
    pq_http_request_t req;
    const char *data = "GET / HTTP/1.1\r\n"
                       "Host: example.com\r\n"
                       "User-Agent: TestClient/1.0\r\n"
                       "Accept: text/html\r\n"
                       "Accept-Encoding: gzip\r\n\r\n";
    size_t consumed = 0;

    pq_http_request_init(&req);

    pq_http_parse_status_t status = pq_http_request_parse(&req, data, strlen(data), &consumed);

    ASSERT(status == HTTP_PARSE_COMPLETE);
    ASSERT(req.header_count == 4);

    ASSERT(pq_http_request_get_header(&req, "Host") != NULL);
    ASSERT(pq_http_request_get_header(&req, "User-Agent") != NULL);
    ASSERT(pq_http_request_get_header(&req, "Accept") != NULL);
    ASSERT(pq_http_request_get_header(&req, "Accept-Encoding") != NULL);

    PASS("test_multiple_headers");
}

/* Test: pq_http_method_str for all methods */
TEST(test_method_strings) {
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_GET), "GET") == 0);
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_POST), "POST") == 0);
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_PUT), "PUT") == 0);
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_DELETE), "DELETE") == 0);
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_PATCH), "PATCH") == 0);
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_HEAD), "HEAD") == 0);
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_OPTIONS), "OPTIONS") == 0);
    ASSERT(strcmp(pq_http_method_str(HTTP_METHOD_CONNECT), "CONNECT") == 0);

    PASS("test_method_strings");
}

/* Test: Malformed request detection */
TEST(test_malformed_request) {
    pq_http_request_t req;
    size_t consumed = 0;

    pq_http_request_init(&req);

    /* Invalid request line */
    const char *garbage = "GARBAGE\r\nBAD\r\n\r\n";
    pq_http_parse_status_t status = pq_http_request_parse(&req, garbage, strlen(garbage), &consumed);

    ASSERT(status == HTTP_PARSE_ERROR);

    PASS("test_malformed_request");
}

/* Test: Request reset and reparse */
TEST(test_request_reset) {
    pq_http_request_t req;
    size_t consumed = 0;

    /* Parse first request */
    pq_http_request_init(&req);
    const char *req1 = "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n";
    pq_http_request_parse(&req, req1, strlen(req1), &consumed);
    ASSERT(strcmp(req.uri, "/first") == 0);

    /* Reset */
    pq_http_request_reset(&req);

    /* Parse second request */
    const char *req2 = "POST /second HTTP/1.1\r\nHost: example.com\r\n\r\n";
    consumed = 0;
    pq_http_request_parse(&req, req2, strlen(req2), &consumed);
    ASSERT(strcmp(req.uri, "/second") == 0);
    ASSERT(req.method == HTTP_METHOD_POST);

    PASS("test_request_reset");
}

/* Test: Case-insensitive header lookup */
TEST(test_header_case_insensitive) {
    pq_http_request_t req;
    const char *data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t consumed = 0;

    pq_http_request_init(&req);
    pq_http_request_parse(&req, data, strlen(data), &consumed);

    /* All these should find the header */
    ASSERT(pq_http_request_get_header(&req, "Host") != NULL);
    ASSERT(pq_http_request_get_header(&req, "host") != NULL);
    ASSERT(pq_http_request_get_header(&req, "HOST") != NULL);
    ASSERT(pq_http_request_get_header(&req, "HoSt") != NULL);

    /* Non-existent header */
    ASSERT(pq_http_request_get_header(&req, "NonExistent") == NULL);

    PASS("test_header_case_insensitive");
}

/* Test: Header overflow protection */
TEST(test_max_header_overflow) {
    pq_http_request_t req;
    size_t consumed = 0;

    pq_http_request_init(&req);

    /* Build a request with headers exceeding PQ_HTTP_MAX_HEADER_SIZE */
    char large_data[PQ_HTTP_MAX_HEADER_SIZE + 1024];
    strcpy(large_data, "GET / HTTP/1.1\r\nHost: example.com\r\n");

    /* Add headers until we exceed the max */
    for (int i = 0; i < 100; i++) {
        strcat(large_data, "X-Custom-Header: value-with-some-data-to-make-it-longer\r\n");
    }
    strcat(large_data, "\r\n");

    pq_http_parse_status_t status = pq_http_request_parse(&req, large_data, strlen(large_data), &consumed);

    /* Should either error or complete, not crash */
    ASSERT(status == HTTP_PARSE_ERROR || status == HTTP_PARSE_COMPLETE);

    PASS("test_max_header_overflow");
}

/* Run all HTTP parser tests */
int run_http_parser_tests(void) {
    test_simple_get();
    test_post_with_content_length();
    test_chunked_transfer();
    test_keep_alive_detection();
    test_incremental_parse();
    test_multiple_headers();
    test_method_strings();
    test_malformed_request();
    test_request_reset();
    test_header_case_insensitive();
    test_max_header_overflow();

    return 0;
}
