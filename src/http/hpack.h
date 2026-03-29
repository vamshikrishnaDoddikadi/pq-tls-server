/*
 * Simplified HPACK Decoder for HTTP/2
 * RFC 7541 - HPACK: Header Compression for HTTP/2
 *
 * This decoder handles:
 * - Static table (RFC 7541 Appendix A)
 * - Dynamic table with eviction
 * - Integer decoding
 * - String decoding (literal strings only)
 * - Indexed header field representation
 * - Literal header with incremental indexing
 * - Literal header without indexing
 */

#ifndef PQ_HTTP_HPACK_H
#define PQ_HTTP_HPACK_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define HPACK_MAX_HEADERS 64
#define HPACK_MAX_TABLE_SIZE 4096
#define HPACK_DYNAMIC_TABLE_SIZE 128

/* Header entry (name-value pair) */
typedef struct {
    char name[256];
    char value[4096];
} hpack_header_t;

/* HPACK decoder state */
typedef struct {
    hpack_header_t dynamic_table[HPACK_DYNAMIC_TABLE_SIZE];
    int            dt_count;
    int            dt_size;      /* Current size in bytes */
    int            max_table_size;
} hpack_decoder_t;

/*
 * Initialize HPACK decoder
 */
void hpack_decoder_init(hpack_decoder_t *dec);

/*
 * Decode a header block
 * buf: pointer to HPACK-encoded header data
 * len: length of header data
 * headers: output array for decoded headers
 * max_headers: maximum number of headers to decode
 *
 * Returns: number of headers decoded (>= 0), or -1 on error
 */
int hpack_decode(hpack_decoder_t *dec, const uint8_t *buf, size_t len,
                 hpack_header_t *headers, int max_headers);

/*
 * Reset decoder (clears dynamic table)
 */
void hpack_decoder_reset(hpack_decoder_t *dec);

#endif /* PQ_HTTP_HPACK_H */
