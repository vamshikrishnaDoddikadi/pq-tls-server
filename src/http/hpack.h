/*
 * HPACK Decoder for HTTP/2
 * RFC 7541 - HPACK: Header Compression for HTTP/2
 *
 * This decoder handles:
 * - Static table (RFC 7541 Appendix A)
 * - Dynamic table with size-based eviction (RFC 7541 Section 4)
 * - Integer decoding with overflow / truncation checks (Section 5.1)
 * - String literals, both raw and Huffman-encoded (Section 5.2, Appendix B)
 * - Indexed header field representation (Section 6.1)
 * - Literal header with / without / never indexing (Section 6.2)
 * - Dynamic table size updates (Section 6.3)
 *
 * Any malformed input is reported as an error (-1), which the caller must
 * treat as a connection error of type COMPRESSION_ERROR (RFC 9113 4.3).
 * The decoder never truncates: a name or value that does not fit in
 * hpack_header_t is an error, not a silently shortened string.
 */

#ifndef PQ_HTTP_HPACK_H
#define PQ_HTTP_HPACK_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define HPACK_MAX_HEADERS 64
#define HPACK_MAX_TABLE_SIZE 4096
/* 4096 / 32 (minimum entry size) = 128 entries at most */
#define HPACK_DYNAMIC_TABLE_SIZE 128

/* Header entry (name-value pair) */
typedef struct {
    char name[256];
    char value[4096];
} hpack_header_t;

/* HPACK decoder state */
typedef struct {
    hpack_header_t dynamic_table[HPACK_DYNAMIC_TABLE_SIZE]; /* ring buffer */
    int            dt_head;      /* Slot of the newest entry (dynamic index 62) */
    int            dt_count;
    int            dt_size;      /* Current size in bytes (RFC 7541 4.1) */
    int            max_table_size;
} hpack_decoder_t;

/*
 * Initialize HPACK decoder
 */
void hpack_decoder_init(hpack_decoder_t *dec);

/*
 * Decode a complete header block
 * buf: pointer to HPACK-encoded header data
 * len: length of header data
 * headers: output array for decoded headers
 * max_headers: capacity of the headers array
 *
 * Returns: number of headers decoded (>= 0), or -1 on error. A block that
 * holds more than max_headers fields is an error (the whole block must be
 * processed to keep the dynamic table in sync, so partial results are
 * never returned).
 */
int hpack_decode(hpack_decoder_t *dec, const uint8_t *buf, size_t len,
                 hpack_header_t *headers, int max_headers);

/*
 * Reset decoder (clears dynamic table)
 */
void hpack_decoder_reset(hpack_decoder_t *dec);

#endif /* PQ_HTTP_HPACK_H */
