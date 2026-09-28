/*
 * HPACK Decoder Implementation
 * RFC 7541
 */

#include "hpack.h"
#include <string.h>
#include <stdio.h>

/* Static table from RFC 7541 Appendix A (first 61 entries) */
typedef struct {
    const char *name;
    const char *value;
} hpack_static_entry_t;

static const hpack_static_entry_t hpack_static_table[] = {
    { ":authority",                ""                      },  /* 1 */
    { ":method",                   "GET"                   },  /* 2 */
    { ":method",                   "POST"                  },  /* 3 */
    { ":path",                     "/"                     },  /* 4 */
    { ":path",                     "/index.html"           },  /* 5 */
    { ":scheme",                   "http"                  },  /* 6 */
    { ":scheme",                   "https"                 },  /* 7 */
    { ":status",                   "200"                   },  /* 8 */
    { ":status",                   "204"                   },  /* 9 */
    { ":status",                   "206"                   },  /* 10 */
    { ":status",                   "304"                   },  /* 11 */
    { ":status",                   "400"                   },  /* 12 */
    { ":status",                   "404"                   },  /* 13 */
    { ":status",                   "500"                   },  /* 14 */
    { "accept-charset",            ""                      },  /* 15 */
    { "accept-encoding",           "gzip, deflate"         },  /* 16 */
    { "accept-language",           ""                      },  /* 17 */
    { "accept-ranges",             ""                      },  /* 18 */
    { "accept",                    ""                      },  /* 19 */
    { "access-control-allow-origin", ""                   },  /* 20 */
    { "age",                       ""                      },  /* 21 */
    { "allow",                     ""                      },  /* 22 */
    { "authorization",             ""                      },  /* 23 */
    { "cache-control",             ""                      },  /* 24 */
    { "content-disposition",       ""                      },  /* 25 */
    { "content-encoding",          ""                      },  /* 26 */
    { "content-language",          ""                      },  /* 27 */
    { "content-length",            ""                      },  /* 28 */
    { "content-location",          ""                      },  /* 29 */
    { "content-range",             ""                      },  /* 30 */
    { "content-type",              ""                      },  /* 31 */
    { "cookie",                    ""                      },  /* 32 */
    { "date",                      ""                      },  /* 33 */
    { "etag",                      ""                      },  /* 34 */
    { "expect",                    ""                      },  /* 35 */
    { "expires",                   ""                      },  /* 36 */
    { "from",                      ""                      },  /* 37 */
    { "host",                      ""                      },  /* 38 */
    { "if-match",                  ""                      },  /* 39 */
    { "if-modified-since",         ""                      },  /* 40 */
    { "if-none-match",             ""                      },  /* 41 */
    { "if-range",                  ""                      },  /* 42 */
    { "if-unmodified-since",       ""                      },  /* 43 */
    { "last-modified",             ""                      },  /* 44 */
    { "link",                      ""                      },  /* 45 */
    { "location",                  ""                      },  /* 46 */
    { "max-forwards",              ""                      },  /* 47 */
    { "proxy-authenticate",        ""                      },  /* 48 */
    { "proxy-authorization",       ""                      },  /* 49 */
    { "range",                     ""                      },  /* 50 */
    { "referer",                   ""                      },  /* 51 */
    { "refresh",                   ""                      },  /* 52 */
    { "retry-after",               ""                      },  /* 53 */
    { "server",                    ""                      },  /* 54 */
    { "set-cookie",                ""                      },  /* 55 */
    { "strict-transport-security", ""                      },  /* 56 */
    { "transfer-encoding",         ""                      },  /* 57 */
    { "user-agent",                ""                      },  /* 58 */
    { "vary",                      ""                      },  /* 59 */
    { "via",                       ""                      },  /* 60 */
    { "www-authenticate",          ""                      },  /* 61 */
};

#define HPACK_STATIC_TABLE_SIZE ((uint32_t)(sizeof(hpack_static_table) / sizeof(hpack_static_table[0])))

/* RFC 7541 4.1: entry size = len(name) + len(value) + 32 */
#define HPACK_ENTRY_OVERHEAD 32

/*
 * Canonical Huffman decoding tables for the RFC 7541 Appendix B code.
 *
 * The HPACK code is canonical (codes of equal length are consecutive and
 * assigned in increasing symbol order) and complete (Kraft sum == 1), so a
 * code of length L is valid iff first[L] <= code < first[L] + count[L], and
 * then decodes to syms[offset[L] + (code - first[L])]. These tables were
 * generated from, and checked against, the Appendix B code table; the unit
 * test (tests/test_hpack.c) re-verifies every symbol against the RFC codes.
 */
/* Symbols ordered by (code length, symbol value); 256 == EOS */
static const uint16_t hpack_huff_syms[257] = {
     48,  49,  50,  97,  99, 101, 105, 111, 115, 116,  32,  37,
     45,  46,  47,  51,  52,  53,  54,  55,  56,  57,  61,  65,
     95,  98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117,
     58,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,
     77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  89,
    106, 107, 113, 118, 119, 120, 121, 122,  38,  42,  44,  59,
     88,  90,  33,  34,  40,  41,  63,  39,  43, 124,  35,  62,
      0,  36,  64,  91,  93, 126,  94, 125,  60,  96, 123,  92,
    195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
    167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129,
    132, 133, 134, 136, 146, 154, 156, 160, 163, 164, 169, 170,
    173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232,
    233,   1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150,
    151, 152, 155, 157, 158, 165, 166, 168, 174, 175, 180, 182,
    183, 188, 191, 197, 231, 239,   9, 142, 144, 145, 148, 159,
    171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193,
    200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242, 243,
    255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245,
    246, 247, 248, 250, 251, 252, 253, 254,   2,   3,   4,   5,
      6,   7,   8,  11,  12,  14,  15,  16,  17,  18,  19,  20,
     21,  23,  24,  25,  26,  27,  28,  29,  30,  31, 127, 220,
    249,  10,  13,  22, 256,
};

/* First canonical code of each bit length (index = length) */
static const uint32_t hpack_huff_first[31] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000014, 0x0000005c, 0x000000f8, 0x00000000, 0x000003f8, 0x000007fa,
    0x00000ffa, 0x00001ff8, 0x00003ffc, 0x00007ffc, 0x00000000, 0x00000000,
    0x00000000, 0x0007fff0, 0x000fffe6, 0x001fffdc, 0x003fffd2, 0x007fffd8,
    0x00ffffea, 0x01ffffec, 0x03ffffe0, 0x07ffffde, 0x0fffffe2, 0x00000000,
    0x3ffffffc,
};

/* Number of codes of each bit length */
static const uint16_t hpack_huff_count[31] = {
      0,   0,   0,   0,   0,  10,  26,  32,   6,   0,   5,   3,   2,   6,   2,   3,
      0,   0,   0,   3,   8,  13,  26,  29,  12,   4,  15,  19,  29,   0,   4,
};

/* Offset into hpack_huff_syms of the first code of each length */
static const uint16_t hpack_huff_offset[31] = {
      0,   0,   0,   0,   0,   0,  10,  36,  68,   0,  74,  79,  82,  84,  90,  92,
      0,   0,   0,  95,  98, 106, 119, 145, 174, 186, 190, 205, 224,   0, 253,
};

#define HPACK_HUFF_EOS     256
#define HPACK_HUFF_MAX_LEN 30

void hpack_decoder_init(hpack_decoder_t *dec)
{
    if (!dec)
        return;
    dec->dt_head = 0;
    dec->dt_count = 0;
    dec->dt_size = 0;
    dec->max_table_size = HPACK_MAX_TABLE_SIZE;
}

void hpack_decoder_reset(hpack_decoder_t *dec)
{
    if (!dec)
        return;
    dec->dt_head = 0;
    dec->dt_count = 0;
    dec->dt_size = 0;
}

/*
 * Decode unsigned integer with prefix (RFC 7541 Section 5.1).
 *
 * Rejects (returns -1):
 *  - truncated input (continuation bit set on the last available octet)
 *  - values that do not fit in 32 bits
 *  - encodings longer than 5 continuation octets (shift would exceed 28)
 */
static int hpack_decode_integer(const uint8_t *buf, size_t len, int prefix_bits,
                                 size_t *consumed, uint32_t *value)
{
    if (!buf || !consumed || !value || len == 0 || prefix_bits < 1 || prefix_bits > 8)
        return -1;

    const uint32_t mask = (1u << prefix_bits) - 1u;
    uint64_t val = buf[0] & mask;

    if (val < mask) {
        *consumed = 1;
        *value = (uint32_t)val;
        return 0;
    }

    /* Multi-byte integer */
    size_t pos = 1;
    unsigned int shift = 0;

    for (;;) {
        if (pos >= len)
            return -1;              /* truncated: continuation expected */
        if (shift > 28)
            return -1;              /* more than 32 bits of payload */

        uint8_t b = buf[pos++];
        val += (uint64_t)(b & 0x7F) << shift;
        if (val > UINT32_MAX)
            return -1;              /* overflow */
        shift += 7;

        if ((b & 0x80) == 0)
            break;
    }

    *consumed = pos;
    *value = (uint32_t)val;
    return 0;
}

/*
 * Decode a Huffman-encoded string (RFC 7541 Section 5.2 / Appendix B).
 * Writes a NUL-terminated string of at most out_len - 1 octets.
 * Returns decoded length, or -1 on error (invalid code, EOS in the
 * string, padding longer than 7 bits or not all ones, or output overflow).
 */
static int hpack_huffman_decode(const uint8_t *src, size_t src_len,
                                char *out, size_t out_len)
{
    uint32_t code = 0;
    unsigned int code_len = 0;
    size_t out_pos = 0;

    for (size_t i = 0; i < src_len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            code = (code << 1) | ((src[i] >> bit) & 1u);
            code_len++;

            if (code_len > HPACK_HUFF_MAX_LEN)
                return -1;          /* cannot happen with a complete code */

            uint32_t count = hpack_huff_count[code_len];
            if (count == 0 || code < hpack_huff_first[code_len])
                continue;
            uint32_t rel = code - hpack_huff_first[code_len];
            if (rel >= count)
                continue;

            uint16_t sym = hpack_huff_syms[hpack_huff_offset[code_len] + rel];
            if (sym == HPACK_HUFF_EOS)
                return -1;          /* 5.2: EOS in a string is an error */
            if (out_pos + 1 >= out_len)
                return -1;          /* does not fit: reject, never truncate */
            out[out_pos++] = (char)sym;
            code = 0;
            code_len = 0;
        }
    }

    /* 5.2: padding must be < 8 bits and consist of the MSBs of EOS (all 1s) */
    if (code_len > 7)
        return -1;
    if (code != (1u << code_len) - 1u)
        return -1;

    out[out_pos] = '\0';
    return (int)out_pos;
}

/*
 * Decode string (RFC 7541 Section 5.2).
 * On success *consumed is the full encoded length (prefix + string octets),
 * independent of the decoded length.
 *
 * Because decoded strings are handled as C strings and may be forwarded to
 * HTTP/1.1 backends, octets NUL, CR and LF are rejected (such fields are
 * malformed per RFC 9113 Section 8.2.1).
 */
static int hpack_decode_string(const uint8_t *buf, size_t len, size_t *consumed,
                                char *out, size_t out_len)
{
    if (!buf || !consumed || !out || len == 0 || out_len == 0)
        return -1;

    int huffman = (buf[0] & 0x80) != 0;
    uint32_t str_len = 0;
    size_t used = 0;

    if (hpack_decode_integer(buf, len, 7, &used, &str_len) < 0)
        return -1;

    if (str_len > len - used)
        return -1;                  /* string extends past the block */

    size_t out_used;
    if (huffman) {
        int n = hpack_huffman_decode(buf + used, str_len, out, out_len);
        if (n < 0)
            return -1;
        out_used = (size_t)n;
    } else {
        if ((size_t)str_len >= out_len)
            return -1;              /* too long: reject, never truncate */
        memcpy(out, buf + used, str_len);
        out[str_len] = '\0';
        out_used = str_len;
    }

    for (size_t i = 0; i < out_used; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c == '\0' || c == '\r' || c == '\n')
            return -1;
    }

    *consumed = used + (size_t)str_len;
    return 0;
}

/* Ring-buffer slot of dynamic table entry i (0 = most recently added) */
static int hpack_dt_slot(const hpack_decoder_t *dec, int i)
{
    return (dec->dt_head + i) % HPACK_DYNAMIC_TABLE_SIZE;
}

static int hpack_entry_size(const hpack_header_t *h)
{
    return (int)(strlen(h->name) + strlen(h->value)) + HPACK_ENTRY_OVERHEAD;
}

/* Evict oldest entries until dt_size <= limit (RFC 7541 4.3 / 4.4) */
static void hpack_evict_to(hpack_decoder_t *dec, int limit)
{
    while (dec->dt_count > 0 && dec->dt_size > limit) {
        int oldest = hpack_dt_slot(dec, dec->dt_count - 1);
        dec->dt_size -= hpack_entry_size(&dec->dynamic_table[oldest]);
        dec->dt_count--;
    }
    if (dec->dt_count == 0) {
        dec->dt_size = 0;
        dec->dt_head = 0;
    }
}

/* Get header from static or dynamic table (RFC 7541 2.3.3) */
static int hpack_get_header(const hpack_decoder_t *dec, uint32_t index,
                            hpack_header_t *header)
{
    if (index == 0)
        return -1;                  /* 6.1: index 0 is a decoding error */

    if (index <= HPACK_STATIC_TABLE_SIZE) {
        /* Static table entry */
        snprintf(header->name, sizeof(header->name), "%s", hpack_static_table[index - 1].name);
        snprintf(header->value, sizeof(header->value), "%s", hpack_static_table[index - 1].value);
        return 0;
    }

    /* Dynamic table entry; unsigned arithmetic, index > static size here */
    uint32_t dyn_index = index - HPACK_STATIC_TABLE_SIZE - 1u;
    if (dec->dt_count <= 0 || dyn_index >= (uint32_t)dec->dt_count)
        return -1;

    memcpy(header, &dec->dynamic_table[hpack_dt_slot(dec, (int)dyn_index)],
           sizeof(hpack_header_t));
    return 0;
}

/* Add entry to dynamic table (RFC 7541 4.4) */
static void hpack_dynamic_table_add(hpack_decoder_t *dec, const hpack_header_t *header)
{
    int entry_size = hpack_entry_size(header);

    if (entry_size > dec->max_table_size) {
        /* 4.4: an entry larger than the table empties it and is not added */
        hpack_evict_to(dec, 0);
        return;
    }

    hpack_evict_to(dec, dec->max_table_size - entry_size);

    /* Defensive: the slot array can hold at most HPACK_DYNAMIC_TABLE_SIZE */
    while (dec->dt_count >= HPACK_DYNAMIC_TABLE_SIZE) {
        int oldest = hpack_dt_slot(dec, dec->dt_count - 1);
        dec->dt_size -= hpack_entry_size(&dec->dynamic_table[oldest]);
        dec->dt_count--;
    }

    dec->dt_head = (dec->dt_head + HPACK_DYNAMIC_TABLE_SIZE - 1) % HPACK_DYNAMIC_TABLE_SIZE;
    memcpy(&dec->dynamic_table[dec->dt_head], header, sizeof(hpack_header_t));
    dec->dt_count++;
    dec->dt_size += entry_size;
}

/*
 * Decode a literal header field (RFC 7541 6.2.x) whose index prefix is
 * prefix_bits wide. On success *pos is advanced past the representation.
 */
static int hpack_decode_literal(const hpack_decoder_t *dec, const uint8_t *buf,
                                size_t len, size_t *pos, int prefix_bits,
                                hpack_header_t *header)
{
    uint32_t index = 0;
    size_t consumed = 0;

    if (hpack_decode_integer(&buf[*pos], len - *pos, prefix_bits, &consumed, &index) < 0)
        return -1;
    *pos += consumed;

    if (index > 0) {
        /* Indexed name */
        if (hpack_get_header(dec, index, header) < 0)
            return -1;
    } else {
        /* Literal name */
        if (*pos >= len)
            return -1;
        if (hpack_decode_string(&buf[*pos], len - *pos, &consumed,
                                header->name, sizeof(header->name)) < 0)
            return -1;
        if (header->name[0] == '\0')
            return -1;              /* empty field name */
        *pos += consumed;
    }

    /* Value is always literal */
    if (*pos >= len)
        return -1;
    if (hpack_decode_string(&buf[*pos], len - *pos, &consumed,
                            header->value, sizeof(header->value)) < 0)
        return -1;
    *pos += consumed;
    return 0;
}

/* Decode HPACK header block */
int hpack_decode(hpack_decoder_t *dec, const uint8_t *buf, size_t len,
                 hpack_header_t *headers, int max_headers)
{
    if (!dec || !headers || max_headers <= 0)
        return -1;
    if (len == 0)
        return 0;                   /* empty header block */
    if (!buf)
        return -1;

    int header_count = 0;
    int field_seen = 0;             /* size updates only allowed before fields */
    size_t pos = 0;

    while (pos < len) {
        uint8_t first = buf[pos];

        if ((first & 0xE0) == 0x20) {
            /* Dynamic table size update (pattern: 001xxxxx), RFC 7541 6.3 */
            uint32_t new_size = 0;
            size_t consumed = 0;

            /* 4.2: must occur at the beginning of a header block */
            if (field_seen)
                return -1;

            if (hpack_decode_integer(&buf[pos], len - pos, 5, &consumed, &new_size) < 0)
                return -1;
            pos += consumed;

            /* 6.3: a value above the protocol limit is a decoding error */
            if (new_size > HPACK_MAX_TABLE_SIZE)
                return -1;

            dec->max_table_size = (int)new_size;
            hpack_evict_to(dec, dec->max_table_size);
            continue;
        }

        field_seen = 1;
        if (header_count >= max_headers)
            return -1;              /* header list too large for caller */

        hpack_header_t *out = &headers[header_count];

        if ((first & 0x80) != 0) {
            /* Indexed header field representation (pattern: 1xxxxxxx) */
            uint32_t index = 0;
            size_t consumed = 0;

            if (hpack_decode_integer(&buf[pos], len - pos, 7, &consumed, &index) < 0)
                return -1;
            pos += consumed;

            if (hpack_get_header(dec, index, out) < 0)
                return -1;

        } else if ((first & 0xC0) == 0x40) {
            /* Literal header with incremental indexing (pattern: 01xxxxxx) */
            if (hpack_decode_literal(dec, buf, len, &pos, 6, out) < 0)
                return -1;
            hpack_dynamic_table_add(dec, out);

        } else {
            /* Literal without indexing (0000xxxx) / never indexed (0001xxxx) */
            if (hpack_decode_literal(dec, buf, len, &pos, 4, out) < 0)
                return -1;
        }

        header_count++;
    }

    return header_count;
}
