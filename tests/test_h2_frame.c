/*
 * test_h2_frame.c - Comprehensive tests for HTTP/2 frame codec
 *
 * Tests HTTP/2 frame header parsing, encoding, and special frames
 * (SETTINGS, GOAWAY).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/* Include the HTTP/2 frame header */
#include "../src/http/h2_frame.h"

/* Simple test framework macros */
#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

/* Helper: create a simple DATA frame header */
static h2_frame_header_t create_test_frame(uint32_t stream_id) {
    h2_frame_header_t frame;
    frame.length = 0;
    frame.type = H2_FRAME_DATA;
    frame.flags = 0;
    frame.stream_id = stream_id;
    return frame;
}

/* Test: Parse and encode frame header (roundtrip) */
TEST(test_parse_frame_header) {
    h2_frame_header_t original = create_test_frame(1);
    original.length = 100;
    original.flags = H2_FLAG_END_STREAM;

    uint8_t buf[H2_FRAME_HEADER_SIZE];

    /* Encode the frame */
    int bytes_written = h2_frame_encode_header(&original, buf, sizeof(buf));
    ASSERT(bytes_written == H2_FRAME_HEADER_SIZE);

    /* Decode it back */
    h2_frame_header_t parsed;
    int bytes_read = h2_frame_parse_header(buf, sizeof(buf), &parsed);
    ASSERT(bytes_read == H2_FRAME_HEADER_SIZE);

    /* Verify roundtrip */
    ASSERT(parsed.length == original.length);
    ASSERT(parsed.type == original.type);
    ASSERT(parsed.flags == original.flags);
    ASSERT(parsed.stream_id == original.stream_id);

    PASS("test_parse_frame_header");
}

/* Test: Encode and verify SETTINGS frame */
TEST(test_settings_frame) {
    uint8_t buf[H2_FRAME_HEADER_SIZE + 6]; /* 9 header + 6 payload */

    int bytes = h2_frame_encode_settings(buf, sizeof(buf), 0);

    ASSERT(bytes > 0);

    /* Verify it's a SETTINGS frame */
    h2_frame_header_t frame;
    h2_frame_parse_header(buf, bytes, &frame);

    ASSERT(frame.type == H2_FRAME_SETTINGS);
    ASSERT(frame.stream_id == 0);  /* SETTINGS always on stream 0 */

    PASS("test_settings_frame");
}

/* Test: Encode SETTINGS ACK frame */
TEST(test_settings_ack_frame) {
    uint8_t buf[H2_FRAME_HEADER_SIZE];

    int bytes = h2_frame_encode_settings(buf, sizeof(buf), 1);  /* ack=1 */

    ASSERT(bytes > 0);

    /* Verify ACK flag */
    h2_frame_header_t frame;
    h2_frame_parse_header(buf, bytes, &frame);

    ASSERT(frame.type == H2_FRAME_SETTINGS);
    ASSERT(frame.flags & 0x01);  /* ACK flag is 0x01 */

    PASS("test_settings_ack_frame");
}

/* Test: Encode GOAWAY frame */
TEST(test_goaway_frame) {
    uint8_t buf[H2_FRAME_HEADER_SIZE + 8];
    uint32_t last_stream = 42;
    uint32_t error_code = H2_PROTOCOL_ERROR;

    int bytes = h2_frame_encode_goaway(buf, sizeof(buf), last_stream, error_code);

    ASSERT(bytes > H2_FRAME_HEADER_SIZE);

    /* Verify frame header */
    h2_frame_header_t frame;
    h2_frame_parse_header(buf, bytes, &frame);

    ASSERT(frame.type == H2_FRAME_GOAWAY);
    ASSERT(frame.stream_id == 0);  /* GOAWAY always on stream 0 */

    PASS("test_goaway_frame");
}

/* Test: Insufficient data for frame parse */
TEST(test_insufficient_data) {
    uint8_t buf[5];  /* Less than H2_FRAME_HEADER_SIZE (9) */
    h2_frame_header_t frame;

    int ret = h2_frame_parse_header(buf, sizeof(buf), &frame);

    ASSERT(ret == -1);  /* Should indicate error */

    PASS("test_insufficient_data");
}

/* Test: Large stream ID (near 2^31) */
TEST(test_large_stream_id) {
    h2_frame_header_t original = create_test_frame(0x7FFFFFFF);  /* Max 31-bit value */
    original.length = 50;

    uint8_t buf[H2_FRAME_HEADER_SIZE];

    int bytes_written = h2_frame_encode_header(&original, buf, sizeof(buf));
    ASSERT(bytes_written == H2_FRAME_HEADER_SIZE);

    h2_frame_header_t parsed;
    int bytes_read = h2_frame_parse_header(buf, sizeof(buf), &parsed);
    ASSERT(bytes_read == H2_FRAME_HEADER_SIZE);

    /* Stream ID should be preserved */
    ASSERT(parsed.stream_id == 0x7FFFFFFF);

    PASS("test_large_stream_id");
}

/* Test: Data frame with payload length */
TEST(test_data_frame_length) {
    h2_frame_header_t original = create_test_frame(3);
    original.length = 1000;
    original.type = H2_FRAME_DATA;

    uint8_t buf[H2_FRAME_HEADER_SIZE];

    int bytes_written = h2_frame_encode_header(&original, buf, sizeof(buf));
    ASSERT(bytes_written == H2_FRAME_HEADER_SIZE);

    h2_frame_header_t parsed;
    h2_frame_parse_header(buf, sizeof(buf), &parsed);

    ASSERT(parsed.length == 1000);
    ASSERT(parsed.type == H2_FRAME_DATA);

    PASS("test_data_frame_length");
}

/* Test: Frame with multiple flags */
TEST(test_frame_flags) {
    h2_frame_header_t original = create_test_frame(5);
    original.type = H2_FRAME_HEADERS;
    original.flags = H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS;

    uint8_t buf[H2_FRAME_HEADER_SIZE];

    int bytes_written = h2_frame_encode_header(&original, buf, sizeof(buf));
    ASSERT(bytes_written == H2_FRAME_HEADER_SIZE);

    h2_frame_header_t parsed;
    h2_frame_parse_header(buf, sizeof(buf), &parsed);

    ASSERT((parsed.flags & H2_FLAG_END_STREAM) != 0);
    ASSERT((parsed.flags & H2_FLAG_END_HEADERS) != 0);

    PASS("test_frame_flags");
}

/* Run all HTTP/2 frame tests */
int run_h2_frame_tests(void) {
    test_parse_frame_header();
    test_settings_frame();
    test_settings_ack_frame();
    test_goaway_frame();
    test_insufficient_data();
    test_large_stream_id();
    test_data_frame_length();
    test_frame_flags();

    return 0;
}
