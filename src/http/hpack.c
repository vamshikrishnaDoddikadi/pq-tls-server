/*
 * HPACK Decoder Implementation
 * RFC 7541
 */

#include "hpack.h"
#include <string.h>
#include <ctype.h>

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

#define HPACK_STATIC_TABLE_SIZE (sizeof(hpack_static_table) / sizeof(hpack_static_table[0]))

void hpack_decoder_init(hpack_decoder_t *dec)
{
    if (!dec)
        return;
    dec->dt_count = 0;
    dec->dt_size = 0;
    dec->max_table_size = HPACK_MAX_TABLE_SIZE;
}

void hpack_decoder_reset(hpack_decoder_t *dec)
{
    if (!dec)
        return;
    dec->dt_count = 0;
    dec->dt_size = 0;
}

/* Decode unsigned integer with prefix (RFC 7541 Section 5.1) */
static int hpack_decode_integer(const uint8_t *buf, size_t len, int prefix_bits,
                                 size_t *consumed, uint32_t *value)
{
    if (!buf || !consumed || !value || len == 0)
        return -1;

    uint8_t mask = (1 << prefix_bits) - 1;
    uint32_t val = buf[0] & mask;
    *consumed = 1;

    if (val < (uint32_t)mask) {
        *value = val;
        return 0;
    }

    /* Multi-byte integer */
    uint32_t m = 0;
    size_t pos = 1;

    while (pos < len) {
        uint8_t b = buf[pos];
        val += (uint32_t)(b & 0x7F) << m;
        *consumed = ++pos;
        m += 7;

        if ((b & 0x80) == 0)
            break;

        if (m > 32)  /* Prevent overflow */
            return -1;
    }

    *value = val;
    return 0;
}

/* Decode string (RFC 7541 Section 5.2) */
static int hpack_decode_string(const uint8_t *buf, size_t len, size_t *consumed,
                                char *out, size_t out_len)
{
    if (!buf || !consumed || !out || len == 0)
        return -1;

    uint8_t first = buf[0];
    int huffman = (first & 0x80) != 0;
    uint32_t str_len = 0;
    size_t used = 0;

    if (hpack_decode_integer(buf, len, 7, &used, &str_len) < 0)
        return -1;

    if (used + str_len > len)
        return -1;

    /* For simplicity, we only handle literal (non-Huffman) strings */
    if (huffman) {
        /* Skip Huffman-encoded data - just store empty string */
        memset(out, 0, out_len);
    } else {
        /* Copy literal string */
        if (str_len >= out_len)
            str_len = out_len - 1;
        memcpy(out, buf + used, str_len);
        out[str_len] = '\0';
    }

    *consumed = used + str_len;
    return 0;
}

/* Get header from static or dynamic table */
static int hpack_get_header(hpack_decoder_t *dec, uint32_t index,
                            hpack_header_t *header)
{
    if (index == 0)
        return -1;

    if (index <= HPACK_STATIC_TABLE_SIZE) {
        /* Static table entry */
        strncpy(header->name, hpack_static_table[index - 1].name, sizeof(header->name) - 1);
        strncpy(header->value, hpack_static_table[index - 1].value, sizeof(header->value) - 1);
        header->name[sizeof(header->name) - 1] = '\0';
        header->value[sizeof(header->value) - 1] = '\0';
        return 0;
    }

    /* Dynamic table entry */
    int dyn_index = index - HPACK_STATIC_TABLE_SIZE - 1;
    if (dyn_index >= dec->dt_count)
        return -1;

    memcpy(header, &dec->dynamic_table[dyn_index], sizeof(hpack_header_t));
    return 0;
}

/* Add entry to dynamic table */
static int hpack_dynamic_table_add(hpack_decoder_t *dec, const hpack_header_t *header)
{
    /* Prevent integer overflow: check bounds before adding */
    size_t name_len = strlen(header->name);
    size_t value_len = strlen(header->value);

    /* RFC 7541: entry size = name length + value length + 32 overhead */
    /* Check for overflow before addition */
    if (name_len > 0x7FFF || value_len > 0x7FFF)
        return 0;  /* Entry too large */

    int entry_size = (int)(name_len + value_len + 32);

    if (entry_size > dec->max_table_size)
        return 0;  /* Entry too large for table */

    /* Evict entries if necessary */
    while (dec->dt_size + entry_size > dec->max_table_size && dec->dt_count > 0) {
        int last = dec->dt_count - 1;
        int evict_size = strlen(dec->dynamic_table[last].name) +
                        strlen(dec->dynamic_table[last].value) + 32;
        dec->dt_size -= evict_size;
        dec->dt_count--;
    }

    /* Shift existing entries and add at head */
    if (dec->dt_count >= HPACK_DYNAMIC_TABLE_SIZE) {
        /* Table is full, shift all entries and drop the last one */
        for (int i = HPACK_DYNAMIC_TABLE_SIZE - 1; i > 0; i--) {
            memcpy(&dec->dynamic_table[i], &dec->dynamic_table[i - 1],
                   sizeof(hpack_header_t));
        }
        /* dt_count stays at max */
    } else {
        /* Table not full, shift and increment count */
        for (int i = dec->dt_count; i > 0; i--) {
            memcpy(&dec->dynamic_table[i], &dec->dynamic_table[i - 1],
                   sizeof(hpack_header_t));
        }
        dec->dt_count++;
    }

    /* Add new entry at head (index 0) */
    memcpy(&dec->dynamic_table[0], header, sizeof(hpack_header_t));
    dec->dt_size += entry_size;

    return 0;
}

/* Decode HPACK header block */
int hpack_decode(hpack_decoder_t *dec, const uint8_t *buf, size_t len,
                 hpack_header_t *headers, int max_headers)
{
    if (!dec || !buf || !headers || max_headers == 0 || len == 0)
        return -1;

    int header_count = 0;
    size_t pos = 0;

    while (pos < len && header_count < max_headers) {
        uint8_t first = buf[pos];

        if ((first & 0x80) != 0) {
            /* Indexed header field representation (pattern: 1xxxxxxx) */
            uint32_t index = 0;
            size_t consumed = 0;

            if (hpack_decode_integer(&buf[pos], len - pos, 7, &consumed, &index) < 0)
                return -1;

            pos += consumed;

            if (hpack_get_header(dec, index, &headers[header_count]) < 0)
                return -1;

            header_count++;

        } else if ((first & 0xC0) == 0x40) {
            /* Literal header with incremental indexing (pattern: 01xxxxxx) */
            uint32_t index = 0;
            size_t consumed = 0;

            if (hpack_decode_integer(&buf[pos], len - pos, 6, &consumed, &index) < 0)
                return -1;

            pos += consumed;

            hpack_header_t header;

            if (index > 0) {
                /* Indexed name */
                if (hpack_get_header(dec, index, &header) < 0)
                    return -1;
            } else {
                /* Literal name */
                if (hpack_decode_string(&buf[pos], len - pos, &consumed,
                                       header.name, sizeof(header.name)) < 0)
                    return -1;
                pos += consumed;
            }

            /* Value is always literal */
            if (hpack_decode_string(&buf[pos], len - pos, &consumed,
                                   header.value, sizeof(header.value)) < 0)
                return -1;
            pos += consumed;

            memcpy(&headers[header_count], &header, sizeof(hpack_header_t));
            hpack_dynamic_table_add(dec, &header);
            header_count++;

        } else if ((first & 0xF0) == 0x00) {
            /* Literal header without indexing (pattern: 0000xxxx) */
            uint32_t index = 0;
            size_t consumed = 0;

            if (hpack_decode_integer(&buf[pos], len - pos, 4, &consumed, &index) < 0)
                return -1;

            pos += consumed;

            hpack_header_t header;

            if (index > 0) {
                if (hpack_get_header(dec, index, &header) < 0)
                    return -1;
            } else {
                if (hpack_decode_string(&buf[pos], len - pos, &consumed,
                                       header.name, sizeof(header.name)) < 0)
                    return -1;
                pos += consumed;
            }

            if (hpack_decode_string(&buf[pos], len - pos, &consumed,
                                   header.value, sizeof(header.value)) < 0)
                return -1;
            pos += consumed;

            memcpy(&headers[header_count], &header, sizeof(hpack_header_t));
            header_count++;

        } else if ((first & 0xE0) == 0x20) {
            /* Dynamic table size update (pattern: 001xxxxx) */
            uint32_t new_size = 0;
            size_t consumed = 0;

            if (hpack_decode_integer(&buf[pos], len - pos, 5, &consumed, &new_size) < 0)
                return -1;

            pos += consumed;

            if (new_size <= HPACK_MAX_TABLE_SIZE) {
                dec->max_table_size = (int)new_size;
                /* Evict entries if necessary */
                while (dec->dt_size > dec->max_table_size && dec->dt_count > 0) {
                    int last = dec->dt_count - 1;
                    int evict_size = strlen(dec->dynamic_table[last].name) +
                                    strlen(dec->dynamic_table[last].value) + 32;
                    dec->dt_size -= evict_size;
                    dec->dt_count--;
                }
            }

        } else {
            /* Literal header never indexed (pattern: 0001xxxx) */
            uint32_t index = 0;
            size_t consumed = 0;

            if (hpack_decode_integer(&buf[pos], len - pos, 4, &consumed, &index) < 0)
                return -1;

            pos += consumed;

            hpack_header_t header;

            if (index > 0) {
                if (hpack_get_header(dec, index, &header) < 0)
                    return -1;
            } else {
                if (hpack_decode_string(&buf[pos], len - pos, &consumed,
                                       header.name, sizeof(header.name)) < 0)
                    return -1;
                pos += consumed;
            }

            if (hpack_decode_string(&buf[pos], len - pos, &consumed,
                                   header.value, sizeof(header.value)) < 0)
                return -1;
            pos += consumed;

            memcpy(&headers[header_count], &header, sizeof(hpack_header_t));
            header_count++;
        }
    }

    return header_count;
}
