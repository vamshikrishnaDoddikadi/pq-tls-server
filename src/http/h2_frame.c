/*
 * HTTP/2 Frame Encoding/Decoding Implementation
 */

#include "h2_frame.h"
#include <string.h>

/*
 * Parse HTTP/2 frame header from buffer
 * Frame header is 9 bytes: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID
 */
int h2_frame_parse_header(const uint8_t *buf, size_t len, h2_frame_header_t *frame)
{
    if (!buf || !frame || len < H2_FRAME_HEADER_SIZE)
        return -1;

    /* Length is 24-bit big-endian */
    frame->length = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | (uint32_t)buf[2];

    /* Type is 1 byte */
    frame->type = buf[3];

    /* Flags is 1 byte */
    frame->flags = buf[4];

    /* Stream ID is 32-bit big-endian, but only 31 bits are used (MSB is reserved) */
    frame->stream_id = (((uint32_t)buf[5] << 24) | ((uint32_t)buf[6] << 16) |
                        ((uint32_t)buf[7] << 8) | (uint32_t)buf[8]) & 0x7FFFFFFFU;

    return H2_FRAME_HEADER_SIZE;
}

/*
 * Encode HTTP/2 frame header to buffer
 */
int h2_frame_encode_header(const h2_frame_header_t *frame, uint8_t *buf, size_t len)
{
    if (!buf || !frame || len < H2_FRAME_HEADER_SIZE)
        return -1;

    /* Length is 24-bit big-endian */
    buf[0] = (frame->length >> 16) & 0xFF;
    buf[1] = (frame->length >> 8) & 0xFF;
    buf[2] = frame->length & 0xFF;

    /* Type is 1 byte */
    buf[3] = frame->type;

    /* Flags is 1 byte */
    buf[4] = frame->flags;

    /* Stream ID is 32-bit big-endian (31 bits used) */
    buf[5] = (frame->stream_id >> 24) & 0xFF;
    buf[6] = (frame->stream_id >> 16) & 0xFF;
    buf[7] = (frame->stream_id >> 8) & 0xFF;
    buf[8] = frame->stream_id & 0xFF;

    return H2_FRAME_HEADER_SIZE;
}

/*
 * Encode SETTINGS frame or SETTINGS ACK
 * ack=1: encode ACK (no payload)
 * ack=0: encode SETTINGS frame with default values
 */
int h2_frame_encode_settings(uint8_t *buf, size_t len, int ack)
{
    h2_frame_header_t frame;
    int payload_len = ack ? 0 : 6;  /* Each setting is 2 bytes ID + 4 bytes value = 6 bytes per setting */

    if (len < (size_t)(H2_FRAME_HEADER_SIZE + payload_len))
        return -1;

    frame.length = payload_len;
    frame.type = H2_FRAME_SETTINGS;
    frame.flags = ack ? 0x01 : 0x00;  /* ACK flag if ack=1 */
    frame.stream_id = 0;  /* Settings are connection-level */

    int hdr_len = h2_frame_encode_header(&frame, buf, len);
    if (hdr_len < 0)
        return -1;

    if (ack)
        return H2_FRAME_HEADER_SIZE;

    /* Encode one default setting: SETTINGS_INITIAL_WINDOW_SIZE = 65535 */
    uint8_t *payload = buf + H2_FRAME_HEADER_SIZE;
    payload[0] = 0x00;
    payload[1] = H2_SETTINGS_INITIAL_WINDOW_SIZE;
    payload[2] = 0x00;
    payload[3] = 0x00;
    payload[4] = 0xFF;
    payload[5] = 0xFF;

    return H2_FRAME_HEADER_SIZE + payload_len;
}

/*
 * Encode GOAWAY frame
 * last_stream: last stream ID processed
 * error_code: error code
 * Payload: 4 bytes last stream ID + 4 bytes error code
 */
int h2_frame_encode_goaway(uint8_t *buf, size_t len, uint32_t last_stream, uint32_t error_code)
{
    h2_frame_header_t frame;
    int payload_len = 8;

    if (len < (size_t)(H2_FRAME_HEADER_SIZE + payload_len))
        return -1;

    frame.length = payload_len;
    frame.type = H2_FRAME_GOAWAY;
    frame.flags = 0x00;
    frame.stream_id = 0;

    int hdr_len = h2_frame_encode_header(&frame, buf, len);
    if (hdr_len < 0)
        return -1;

    uint8_t *payload = buf + H2_FRAME_HEADER_SIZE;

    /* Last stream ID (31-bit, MSB reserved) */
    last_stream &= 0x7FFFFFFFU;
    payload[0] = (last_stream >> 24) & 0xFF;
    payload[1] = (last_stream >> 16) & 0xFF;
    payload[2] = (last_stream >> 8) & 0xFF;
    payload[3] = last_stream & 0xFF;

    /* Error code (32-bit) */
    payload[4] = (error_code >> 24) & 0xFF;
    payload[5] = (error_code >> 16) & 0xFF;
    payload[6] = (error_code >> 8) & 0xFF;
    payload[7] = error_code & 0xFF;

    return H2_FRAME_HEADER_SIZE + payload_len;
}

/*
 * Encode WINDOW_UPDATE frame
 * stream_id: stream ID (0 for connection window)
 * increment: window size increment (31-bit)
 * Payload: 4 bytes (31-bit increment, MSB reserved)
 */
int h2_frame_encode_window_update(uint8_t *buf, size_t len, uint32_t stream_id, uint32_t increment)
{
    h2_frame_header_t frame;
    int payload_len = 4;

    if (len < (size_t)(H2_FRAME_HEADER_SIZE + payload_len))
        return -1;

    frame.length = payload_len;
    frame.type = H2_FRAME_WINDOW_UPDATE;
    frame.flags = 0x00;
    frame.stream_id = stream_id & 0x7FFFFFFFU;

    int hdr_len = h2_frame_encode_header(&frame, buf, len);
    if (hdr_len < 0)
        return -1;

    uint8_t *payload = buf + H2_FRAME_HEADER_SIZE;

    /* Window increment (31-bit, MSB reserved) */
    increment &= 0x7FFFFFFFU;
    payload[0] = (increment >> 24) & 0xFF;
    payload[1] = (increment >> 16) & 0xFF;
    payload[2] = (increment >> 8) & 0xFF;
    payload[3] = increment & 0xFF;

    return H2_FRAME_HEADER_SIZE + payload_len;
}

/*
 * Encode PING ACK frame
 * opaque_data: 8 bytes of opaque data from received PING
 * Payload: 8 bytes of opaque data
 */
int h2_frame_encode_ping_ack(uint8_t *buf, size_t len, const uint8_t *opaque_data)
{
    h2_frame_header_t frame;
    int payload_len = 8;

    if (!opaque_data || len < (size_t)(H2_FRAME_HEADER_SIZE + payload_len))
        return -1;

    frame.length = payload_len;
    frame.type = H2_FRAME_PING;
    frame.flags = 0x01;  /* ACK flag */
    frame.stream_id = 0;

    int hdr_len = h2_frame_encode_header(&frame, buf, len);
    if (hdr_len < 0)
        return -1;

    /* Copy opaque data */
    memcpy(buf + H2_FRAME_HEADER_SIZE, opaque_data, payload_len);

    return H2_FRAME_HEADER_SIZE + payload_len;
}
