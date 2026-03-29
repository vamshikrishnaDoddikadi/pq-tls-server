/*
 * HTTP/2 Frame Definitions and Encoding/Decoding
 * RFC 7540
 */

#ifndef PQ_HTTP_H2_FRAME_H
#define PQ_HTTP_H2_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define H2_FRAME_HEADER_SIZE  9

/* Frame types */
typedef enum {
    H2_FRAME_DATA          = 0x00,
    H2_FRAME_HEADERS       = 0x01,
    H2_FRAME_PRIORITY      = 0x02,
    H2_FRAME_RST_STREAM    = 0x03,
    H2_FRAME_SETTINGS      = 0x04,
    H2_FRAME_PUSH_PROMISE  = 0x05,
    H2_FRAME_PING          = 0x06,
    H2_FRAME_GOAWAY        = 0x07,
    H2_FRAME_WINDOW_UPDATE = 0x08,
    H2_FRAME_CONTINUATION  = 0x09
} h2_frame_type_t;

/* Frame flags */
#define H2_FLAG_END_STREAM   0x01
#define H2_FLAG_END_HEADERS  0x04
#define H2_FLAG_PADDED       0x08
#define H2_FLAG_PRIORITY     0x20

/* Settings identifiers */
#define H2_SETTINGS_HEADER_TABLE_SIZE      0x01
#define H2_SETTINGS_ENABLE_PUSH            0x02
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x03
#define H2_SETTINGS_INITIAL_WINDOW_SIZE    0x04
#define H2_SETTINGS_MAX_FRAME_SIZE         0x05
#define H2_SETTINGS_MAX_HEADER_LIST_SIZE   0x06

/* Error codes */
#define H2_NO_ERROR            0x00
#define H2_PROTOCOL_ERROR      0x01
#define H2_INTERNAL_ERROR      0x02
#define H2_FLOW_CONTROL_ERROR  0x03
#define H2_COMPRESSION_ERROR   0x09

/* HTTP/2 client preface */
#define H2_CLIENT_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_CLIENT_PREFACE_LEN 24

/* Frame header structure */
typedef struct {
    uint32_t length;     /* 24-bit payload length */
    uint8_t  type;       /* Frame type */
    uint8_t  flags;      /* Frame flags */
    uint32_t stream_id;  /* 31-bit stream ID (MSB is reserved) */
} h2_frame_header_t;

/* Settings frame value */
typedef struct {
    uint16_t identifier;
    uint32_t value;
} h2_settings_t;

/*
 * Parse HTTP/2 frame header from buffer
 * Returns 0 on success, -1 if insufficient data
 */
int h2_frame_parse_header(const uint8_t *buf, size_t len, h2_frame_header_t *frame);

/*
 * Encode HTTP/2 frame header to buffer
 * Returns bytes written or -1 on error
 */
int h2_frame_encode_header(const h2_frame_header_t *frame, uint8_t *buf, size_t len);

/*
 * Encode SETTINGS frame or SETTINGS ACK
 * ack=1 for ACK (no payload), ack=0 for initial settings
 * Returns bytes written or -1 on error
 */
int h2_frame_encode_settings(uint8_t *buf, size_t len, int ack);

/*
 * Encode GOAWAY frame
 * last_stream: last stream ID processed
 * error_code: error code
 * Returns bytes written or -1 on error
 */
int h2_frame_encode_goaway(uint8_t *buf, size_t len, uint32_t last_stream, uint32_t error_code);

/*
 * Encode WINDOW_UPDATE frame
 * stream_id: stream ID (0 for connection window)
 * increment: window size increment
 * Returns bytes written or -1 on error
 */
int h2_frame_encode_window_update(uint8_t *buf, size_t len, uint32_t stream_id, uint32_t increment);

/*
 * Encode PING ACK frame
 * opaque_data: 8 bytes of opaque data from received PING
 * Returns bytes written or -1 on error
 */
int h2_frame_encode_ping_ack(uint8_t *buf, size_t len, const uint8_t *opaque_data);

#endif /* PQ_HTTP_H2_FRAME_H */
