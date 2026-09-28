/*
 * test_hpack.c - Tests for the HPACK decoder (RFC 7541)
 *
 * Covers RFC 7541 Appendix C examples (raw and Huffman), integer
 * overflow/truncation, index validation, string length handling, dynamic
 * table eviction rules and size updates.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/http/hpack.h"

#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

/* hpack_decoder_t is ~550 KB; keep it off the stack */
static hpack_decoder_t g_dec;
static hpack_header_t  g_hdrs[HPACK_MAX_HEADERS];

/* RFC 7541 Appendix B: code value (right-aligned) and bit length for
 * symbols 0..255 plus EOS (256). Independent of the decoder's canonical
 * tables, so the round-trip test cross-checks them. */
static const uint32_t rfc7541_huff_codes[257] = {
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
    0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
    0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
    0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
    0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    0x3fffffff,
};

static const uint8_t rfc7541_huff_lens[257] = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
};

/* ---- helpers --------------------------------------------------------- */

static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    int hi = -1;
    for (const char *p = hex; *p; p++) {
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if (hi < 0) {
            hi = v;
        } else {
            ASSERT(n < cap);
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    ASSERT(hi < 0);
    return n;
}

static int decode_hex(const char *hex)
{
    uint8_t buf[512];
    size_t len = hex_to_bytes(hex, buf, sizeof(buf));
    return hpack_decode(&g_dec, buf, len, g_hdrs, HPACK_MAX_HEADERS);
}

static void expect_hdr(int i, const char *name, const char *value)
{
    if (strcmp(g_hdrs[i].name, name) != 0 || strcmp(g_hdrs[i].value, value) != 0) {
        fprintf(stderr, "header %d: got '%s: %s', want '%s: %s'\n",
                i, g_hdrs[i].name, g_hdrs[i].value, name, value);
        ASSERT(0);
    }
}

/* Encode an HPACK integer with the given prefix; first-byte flags in 'flags' */
static size_t enc_int(uint8_t *out, uint8_t flags, int prefix_bits, uint32_t v)
{
    uint32_t max = (1u << prefix_bits) - 1u;
    size_t n = 0;
    if (v < max) {
        out[n++] = (uint8_t)(flags | v);
        return n;
    }
    out[n++] = (uint8_t)(flags | max);
    v -= max;
    while (v >= 128) {
        out[n++] = (uint8_t)((v & 0x7F) | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

/* Huffman-encode using the RFC table; returns encoded length */
static size_t huff_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t cap)
{
    uint64_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << rfc7541_huff_lens[in[i]]) | rfc7541_huff_codes[in[i]];
        bits += rfc7541_huff_lens[in[i]];
        while (bits >= 8) {
            ASSERT(n < cap);
            out[n++] = (uint8_t)(acc >> (bits - 8));
            bits -= 8;
        }
    }
    if (bits > 0) {
        ASSERT(n < cap);
        /* pad with the MSBs of EOS (all ones) */
        out[n++] = (uint8_t)((acc << (8 - bits)) | ((1u << (8 - bits)) - 1u));
    }
    return n;
}

/* ---- RFC 7541 Appendix C -------------------------------------------- */

TEST(test_rfc7541_c3_raw_requests) {
    hpack_decoder_init(&g_dec);

    ASSERT(decode_hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d") == 4);
    expect_hdr(0, ":method", "GET");
    expect_hdr(1, ":scheme", "http");
    expect_hdr(2, ":path", "/");
    expect_hdr(3, ":authority", "www.example.com");
    ASSERT(g_dec.dt_count == 1 && g_dec.dt_size == 57);

    ASSERT(decode_hex("8286 84be 5808 6e6f 2d63 6163 6865") == 5);
    expect_hdr(3, ":authority", "www.example.com");
    expect_hdr(4, "cache-control", "no-cache");
    ASSERT(g_dec.dt_count == 2 && g_dec.dt_size == 110);

    ASSERT(decode_hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 "
                      "0c63 7573 746f 6d2d 7661 6c75 65") == 5);
    expect_hdr(1, ":scheme", "https");
    expect_hdr(2, ":path", "/index.html");
    expect_hdr(3, ":authority", "www.example.com");
    expect_hdr(4, "custom-key", "custom-value");
    ASSERT(g_dec.dt_count == 3 && g_dec.dt_size == 164);

    PASS("test_rfc7541_c3_raw_requests");
}

TEST(test_rfc7541_c4_huffman_requests) {
    hpack_decoder_init(&g_dec);

    ASSERT(decode_hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff") == 4);
    expect_hdr(0, ":method", "GET");
    expect_hdr(1, ":scheme", "http");
    expect_hdr(2, ":path", "/");
    expect_hdr(3, ":authority", "www.example.com");
    ASSERT(g_dec.dt_count == 1 && g_dec.dt_size == 57);

    ASSERT(decode_hex("8286 84be 5886 a8eb 1064 9cbf") == 5);
    expect_hdr(3, ":authority", "www.example.com");
    expect_hdr(4, "cache-control", "no-cache");
    ASSERT(g_dec.dt_count == 2 && g_dec.dt_size == 110);

    ASSERT(decode_hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 "
                      "a849 e95b b8e8 b4bf") == 5);
    expect_hdr(1, ":scheme", "https");
    expect_hdr(2, ":path", "/index.html");
    expect_hdr(3, ":authority", "www.example.com");
    expect_hdr(4, "custom-key", "custom-value");
    ASSERT(g_dec.dt_count == 3 && g_dec.dt_size == 164);

    PASS("test_rfc7541_c4_huffman_requests");
}

/* C.6: Huffman responses with a 256-octet table, exercising eviction */
TEST(test_rfc7541_c6_huffman_responses_eviction) {
    hpack_decoder_init(&g_dec);

    /* 3fe101 = dynamic table size update to 256, then C.6.1 */
    ASSERT(decode_hex("3fe101 "
                      "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 "
                      "2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 "
                      "8f0b 97c8 e9ae 82ae 43d3") == 4);
    ASSERT(g_dec.max_table_size == 256);
    expect_hdr(0, ":status", "302");
    expect_hdr(1, "cache-control", "private");
    expect_hdr(2, "date", "Mon, 21 Oct 2013 20:13:21 GMT");
    expect_hdr(3, "location", "https://www.example.com");
    ASSERT(g_dec.dt_count == 4 && g_dec.dt_size == 222);

    ASSERT(decode_hex("4883 640e ffc1 c0bf") == 4);
    expect_hdr(0, ":status", "307");
    expect_hdr(1, "cache-control", "private");
    expect_hdr(2, "date", "Mon, 21 Oct 2013 20:13:21 GMT");
    expect_hdr(3, "location", "https://www.example.com");
    ASSERT(g_dec.dt_count == 4 && g_dec.dt_size == 222);

    ASSERT(decode_hex("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 "
                      "e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 "
                      "e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 "
                      "0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07") == 6);
    expect_hdr(0, ":status", "200");
    expect_hdr(1, "cache-control", "private");
    expect_hdr(2, "date", "Mon, 21 Oct 2013 20:13:22 GMT");
    expect_hdr(3, "location", "https://www.example.com");
    expect_hdr(4, "content-encoding", "gzip");
    expect_hdr(5, "set-cookie",
               "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
    ASSERT(g_dec.dt_count == 3 && g_dec.dt_size == 215);

    PASS("test_rfc7541_c6_huffman_responses_eviction");
}

/* ---- Huffman: every symbol, and invalid encodings -------------------- */

TEST(test_huffman_all_symbols_roundtrip) {
    uint8_t plain[256];
    size_t plain_len = 0;
    for (int c = 1; c < 256; c++) {
        if (c == '\r' || c == '\n')
            continue;               /* rejected by design, tested below */
        plain[plain_len++] = (uint8_t)c;
    }

    static uint8_t huff[1024];
    size_t huff_len = huff_encode(plain, plain_len, huff, sizeof(huff));

    static uint8_t block[1100];
    size_t n = 0;
    block[n++] = 0x00;              /* literal without indexing, new name */
    block[n++] = 0x01;              /* raw name, length 1 */
    block[n++] = 'x';
    n += enc_int(&block[n], 0x80, 7, (uint32_t)huff_len);
    memcpy(&block[n], huff, huff_len);
    n += huff_len;

    hpack_decoder_init(&g_dec);
    ASSERT(hpack_decode(&g_dec, block, n, g_hdrs, HPACK_MAX_HEADERS) == 1);
    ASSERT(strcmp(g_hdrs[0].name, "x") == 0);
    ASSERT(strlen(g_hdrs[0].value) == plain_len);
    ASSERT(memcmp(g_hdrs[0].value, plain, plain_len) == 0);

    /* NUL, CR and LF in a (Huffman) value are rejected */
    const uint8_t bad_syms[3] = { 0x00, '\r', '\n' };
    for (int i = 0; i < 3; i++) {
        uint8_t v[3] = { 'a', bad_syms[i], 'b' };
        uint8_t h[16];
        size_t hl = huff_encode(v, 3, h, sizeof(h));
        n = 0;
        block[n++] = 0x00;
        block[n++] = 0x01;
        block[n++] = 'x';
        n += enc_int(&block[n], 0x80, 7, (uint32_t)hl);
        memcpy(&block[n], h, hl);
        n += hl;
        hpack_decoder_init(&g_dec);
        ASSERT(hpack_decode(&g_dec, block, n, g_hdrs, HPACK_MAX_HEADERS) == -1);
    }

    PASS("test_huffman_all_symbols_roundtrip");
}

TEST(test_huffman_invalid) {
    /* Valid baseline: 'a' (00011) + 3 padding ones = 0x1f */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("00 0178 81 1f") == 1);
    expect_hdr(0, "x", "a");

    /* EOS inside the string (30 ones + 2 padding ones) */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("00 0178 84 ffffffff") == -1);

    /* Padding longer than 7 bits */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("00 0178 82 1fff") == -1);

    /* Padding not made of ones */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("00 0178 81 18") == -1);

    PASS("test_huffman_invalid");
}

/* ---- Integer decoding ------------------------------------------------ */

TEST(test_integer_truncated_and_overflow) {
    /* Size update with prefix saturated but no continuation octet */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("3f") == -1);
    ASSERT(g_dec.max_table_size == HPACK_MAX_TABLE_SIZE);

    /* Continuation bit set on the last octet */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("3f80") == -1);
    ASSERT(g_dec.max_table_size == HPACK_MAX_TABLE_SIZE);

    /* Bits shifted past 32 at m=28 used to be silently dropped (-> 31) */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("3f 80 80 80 80 10") == -1);
    ASSERT(g_dec.max_table_size == HPACK_MAX_TABLE_SIZE);

    /* Too many continuation octets */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("3f 80 80 80 80 80 80 00") == -1);

    /* Value > UINT32_MAX */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("ff ff ff ff ff 0f") == -1);

    /* Truncated string length */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("00 7f") == -1);

    PASS("test_integer_truncated_and_overflow");
}

/* ---- Index validation ------------------------------------------------ */

TEST(test_index_validation) {
    /* Index 0 */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("80") == -1);

    /* Index 0xFFFFFFFF: (int)(index - 62) used to go negative -> OOB read */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("ff 80 ff ff ff 0f") == -1);

    /* Index 0x80000000 + 62 */
    hpack_decoder_init(&g_dec);
    {
        uint8_t b[8];
        size_t n = enc_int(b, 0x80, 7, 0x80000000u + 62u);
        ASSERT(hpack_decode(&g_dec, b, n, g_hdrs, HPACK_MAX_HEADERS) == -1);
    }

    /* Same for a literal with an indexed name (incremental indexing) */
    hpack_decoder_init(&g_dec);
    {
        uint8_t b[16];
        size_t n = enc_int(b, 0x40, 6, 0xFFFFFFF0u);
        b[n++] = 0x01;
        b[n++] = 'a';
        ASSERT(hpack_decode(&g_dec, b, n, g_hdrs, HPACK_MAX_HEADERS) == -1);
        ASSERT(g_dec.dt_count == 0);
    }

    /* First dynamic index with an empty table */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("be") == -1);

    /* Last static index is fine, first dynamic index after one insert too */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("bd") == 1);
    expect_hdr(0, "www-authenticate", "");
    ASSERT(decode_hex("40 0161 0162 be") == 2);
    expect_hdr(1, "a", "b");
    ASSERT(decode_hex("bf") == -1);

    PASS("test_index_validation");
}

/* ---- String length handling ----------------------------------------- */

TEST(test_oversized_string_rejected_not_truncated) {
    /*
     * A 5000-octet value used to be truncated to 4095 octets while the
     * parser only advanced by 4095, so the tail of the value was parsed as
     * further header representations (header injection). Now: error.
     */
    static uint8_t block[6000];
    size_t n = 0;
    block[n++] = 0x00;
    block[n++] = 0x03;
    memcpy(&block[n], "x-a", 3);
    n += 3;
    n += enc_int(&block[n], 0x00, 7, 5000);
    memset(&block[n], 'v', 5000);
    block[n + 4095] = 0x82;         /* would decode as ":method: GET" */
    n += 5000;

    hpack_decoder_init(&g_dec);
    ASSERT(hpack_decode(&g_dec, block, n, g_hdrs, HPACK_MAX_HEADERS) == -1);

    /* Name longer than 255 octets */
    n = 0;
    block[n++] = 0x00;
    n += enc_int(&block[n], 0x00, 7, 256);
    memset(&block[n], 'n', 256);
    n += 256;
    block[n++] = 0x01;
    block[n++] = 'v';
    hpack_decoder_init(&g_dec);
    ASSERT(hpack_decode(&g_dec, block, n, g_hdrs, HPACK_MAX_HEADERS) == -1);

    /* Largest value that fits (4095) still works */
    n = 0;
    block[n++] = 0x00;
    block[n++] = 0x01;
    block[n++] = 'x';
    n += enc_int(&block[n], 0x00, 7, 4095);
    memset(&block[n], 'v', 4095);
    n += 4095;
    hpack_decoder_init(&g_dec);
    ASSERT(hpack_decode(&g_dec, block, n, g_hdrs, HPACK_MAX_HEADERS) == 1);
    ASSERT(strlen(g_hdrs[0].value) == 4095);

    /* String length beyond the block */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("00 0178 05 6162") == -1);

    /* Embedded NUL / CR / LF in raw strings */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("00 0178 03 610062") == -1);
    ASSERT(decode_hex("00 0178 03 610d62") == -1);
    ASSERT(decode_hex("00 0178 03 610a62") == -1);

    /* Empty literal name */
    ASSERT(decode_hex("00 00 0161") == -1);

    PASS("test_oversized_string_rejected_not_truncated");
}

/* ---- Dynamic table rules --------------------------------------------- */

TEST(test_entry_larger_than_table_empties_it) {
    hpack_decoder_init(&g_dec);

    /* Size update to 64, then add a:b (size 34) */
    ASSERT(decode_hex("3f21 40 0161 0162") == 1);
    ASSERT(g_dec.max_table_size == 64);
    ASSERT(g_dec.dt_count == 1 && g_dec.dt_size == 34);

    /* n: <40 x 'v'> has size 73 > 64: RFC 7541 4.4 -> table emptied */
    char hex[256];
    int off = snprintf(hex, sizeof(hex), "40 016e 28 ");
    for (int i = 0; i < 40; i++)
        off += snprintf(hex + off, sizeof(hex) - (size_t)off, "76");
    ASSERT(decode_hex(hex) == 1);
    expect_hdr(0, "n", "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv");
    ASSERT(g_dec.dt_count == 0 && g_dec.dt_size == 0);

    /* The old a:b entry must be gone */
    ASSERT(decode_hex("be") == -1);

    PASS("test_entry_larger_than_table_empties_it");
}

TEST(test_table_size_update_rules) {
    /* Exactly the maximum is accepted */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("3fe11f 82") == 1);
    ASSERT(g_dec.max_table_size == 4096);

    /* Above the maximum is an error */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("3fe21f 82") == -1);

    /* Size update after a header field is an error (RFC 7541 4.2) */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("82 20") == -1);

    /* Shrinking evicts, size 0 clears the table */
    hpack_decoder_init(&g_dec);
    ASSERT(decode_hex("40 0161 0162 40 0163 0164") == 2);
    ASSERT(g_dec.dt_count == 2 && g_dec.dt_size == 68);
    ASSERT(decode_hex("3f03 82") == 1);   /* size 34: keeps newest only */
    ASSERT(g_dec.dt_count == 1 && g_dec.dt_size == 34);
    ASSERT(decode_hex("be") == 1);
    expect_hdr(0, "c", "d");
    ASSERT(decode_hex("20 82") == 1);     /* size 0 */
    ASSERT(g_dec.dt_count == 0 && g_dec.dt_size == 0);

    PASS("test_table_size_update_rules");
}

TEST(test_dynamic_table_ring_wraparound) {
    hpack_decoder_init(&g_dec);

    /* 300 entries "kNNN: v" (size 32 + 4 + 1 = 37) -> 4096/37 = 110 kept */
    for (int i = 0; i < 300; i++) {
        char hex[64];
        snprintf(hex, sizeof(hex), "40 04 6b%02x%02x%02x 01 76",
                 '0' + (i / 100), '0' + (i / 10) % 10, '0' + i % 10);
        ASSERT(decode_hex(hex) == 1);
    }
    ASSERT(g_dec.dt_count == 4096 / 37);
    ASSERT(g_dec.dt_size == (4096 / 37) * 37);

    /* Index 62 is the newest, 62 + count - 1 the oldest kept */
    ASSERT(decode_hex("be") == 1);
    expect_hdr(0, "k299", "v");
    {
        uint8_t b[8];
        size_t n = enc_int(b, 0x80, 7, 62u + (uint32_t)g_dec.dt_count - 1u);
        ASSERT(hpack_decode(&g_dec, b, n, g_hdrs, HPACK_MAX_HEADERS) == 1);
        char want[16];
        snprintf(want, sizeof(want), "k%03d", 300 - g_dec.dt_count);
        expect_hdr(0, want, "v");
        n = enc_int(b, 0x80, 7, 62u + (uint32_t)g_dec.dt_count);
        ASSERT(hpack_decode(&g_dec, b, n, g_hdrs, HPACK_MAX_HEADERS) == -1);
    }

    PASS("test_dynamic_table_ring_wraparound");
}

TEST(test_too_many_headers_is_error) {
    hpack_decoder_init(&g_dec);
    uint8_t buf[3] = { 0x82, 0x84, 0x86 };
    ASSERT(hpack_decode(&g_dec, buf, 3, g_hdrs, 2) == -1);
    ASSERT(hpack_decode(&g_dec, buf, 3, g_hdrs, 3) == 3);
    ASSERT(hpack_decode(&g_dec, buf, 0, g_hdrs, 3) == 0);
    PASS("test_too_many_headers_is_error");
}

int run_hpack_tests(void) {
    test_rfc7541_c3_raw_requests();
    test_rfc7541_c4_huffman_requests();
    test_rfc7541_c6_huffman_responses_eviction();
    test_huffman_all_symbols_roundtrip();
    test_huffman_invalid();
    test_integer_truncated_and_overflow();
    test_index_validation();
    test_oversized_string_rejected_not_truncated();
    test_entry_larger_than_table_empties_it();
    test_table_size_update_rules();
    test_dynamic_table_ring_wraparound();
    test_too_many_headers_is_error();
    return 0;
}
