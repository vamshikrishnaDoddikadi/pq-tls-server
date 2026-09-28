/**
 * @file http_rewriter.c
 * @brief Streaming HTTP/1.x request rewriter (see http_rewriter.h)
 *
 * Framing rules follow RFC 9112 §6 (message body length) and §7.1 (chunked
 * transfer coding); anything ambiguous is rejected rather than guessed, since
 * a disagreement between this proxy and the backend about where a request
 * ends is exactly what request smuggling exploits.
 *
 * @author Vamshi Krishna Doddikadi
 */

#include "http_rewriter.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define PQ_RW_MAX_LINE 4096  /* chunk-size line or single trailer line */

typedef enum {
    ST_HEAD,         /* accumulating a request head                 */
    ST_BODY,         /* forwarding a Content-Length body            */
    ST_CHUNK_SIZE,   /* reading a chunk-size line                   */
    ST_CHUNK_DATA,   /* forwarding chunk data                       */
    ST_CHUNK_CRLF,   /* expecting the CRLF that ends chunk data     */
    ST_TRAILER,      /* reading trailer fields after the last chunk */
    ST_AWAIT,        /* Upgrade/CONNECT sent, waiting for response  */
    ST_PASSTHROUGH,  /* byte-for-byte relay                         */
    ST_ERROR
} rw_state_t;

struct pq_http_rewriter {
    rw_state_t    st;
    int           err;
    int           first;            /* no request seen yet */
    unsigned long requests;

    unsigned char head[PQ_RW_MAX_HEAD];
    size_t        head_len;

    uint64_t      remaining;        /* ST_BODY / ST_CHUNK_DATA */
    int           crlf_pos;         /* ST_CHUNK_CRLF */
    unsigned char line[PQ_RW_MAX_LINE];
    size_t        line_len;
    size_t        trailer_bytes;

    int           await_after_body; /* request asked for Upgrade/CONNECT */
    int           await_connect;    /* 1 = CONNECT (2xx), 0 = Upgrade (101) */
    unsigned char status[12];
    size_t        status_len;
    unsigned char *pending;         /* client bytes received during ST_AWAIT */
    size_t        pending_len;

    char          inject[PQ_RW_MAX_INJECT];
    size_t        inject_len;
    unsigned char out[PQ_RW_MAX_HEAD + PQ_RW_MAX_INJECT + 8];
};

/* ======================================================================== */
/* Character classes (RFC 9110 §5.6)                                        */
/* ======================================================================== */

static int is_tchar(unsigned char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return 1;
    return c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

/* field-vchar / SP / HTAB, including obs-text */
static int is_field_char(unsigned char c) {
    return c == '\t' || c == ' ' || (c >= 0x21 && c != 0x7f);
}

static int is_ows(unsigned char c) { return c == ' ' || c == '\t'; }

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Case-insensitive name comparison that also treats '_' as '-', because
 * CGI/WSGI-style backends map both to '_' ("X_Forwarded_For" would otherwise
 * smuggle a spoofed HTTP_X_FORWARDED_FOR past the filter). */
static int name_eq(const unsigned char *name, size_t len, const char *lit) {
    size_t n = strlen(lit);
    if (len != n) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char a = name[i], b = (unsigned char)lit[i];
        if (a == '_') a = '-';
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

/* Headers the proxy owns: removed from client input, set by the proxy. */
static int is_managed_header(const unsigned char *name, size_t len) {
    static const char *const managed[] = {
        "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
        "x-forwarded-port", "x-real-ip", "forwarded", NULL
    };
    for (int i = 0; managed[i]; i++) {
        if (name_eq(name, len, managed[i])) return 1;
    }
    return len >= 5 && name_eq(name, 5, "x-pq-");
}

/* ======================================================================== */
/* Helpers                                                                  */
/* ======================================================================== */

static int fail(pq_http_rewriter_t *rw, int code) {
    rw->st = ST_ERROR;
    rw->err = code;
    return code;
}

static int emit_or_fail(pq_http_rewriter_t *rw, pq_rw_emit_fn emit, void *ctx,
                        const void *data, size_t len) {
    if (len == 0) return PQ_RW_OK;
    if (emit(ctx, data, len) != 0) return fail(rw, PQ_RW_EMIT_FAILED);
    return PQ_RW_OK;
}

static void finish_request(pq_http_rewriter_t *rw) {
    rw->head_len = 0;
    rw->line_len = 0;
    if (rw->await_after_body) {
        rw->await_after_body = 0;
        rw->status_len = 0;
        rw->st = ST_AWAIT;
    } else {
        rw->st = ST_HEAD;
    }
}

/* Validate "name: value" (no CRLF). Returns length of the name, or 0 if the
 * line is not a well-formed field line. Sets v0..v1 to the trimmed value. */
static size_t parse_field_line(const unsigned char *line, size_t len,
                               size_t *v0, size_t *v1) {
    if (len == 0 || is_ows(line[0])) return 0;          /* obs-fold */
    if (memchr(line, '\r', len)) return 0;               /* bare CR */
    size_t c = 0;
    while (c < len && is_tchar(line[c])) c++;
    if (c == 0 || c >= len || line[c] != ':') return 0;  /* incl. "Name :" */
    size_t a = c + 1, b = len;
    while (a < b && is_ows(line[a])) a++;
    while (b > a && is_ows(line[b - 1])) b--;
    for (size_t i = a; i < b; i++) {
        if (!is_field_char(line[i])) return 0;
    }
    *v0 = a;
    *v1 = b;
    return c;
}

/* Iterate comma-separated list elements of a field value, trimming OWS and
 * stripping ";params". Returns 0 when exhausted. */
static int next_list_elem(const unsigned char *v, size_t len, size_t *pos,
                          const unsigned char **tok, size_t *tok_len) {
    while (*pos < len) {
        size_t s = *pos;
        while (*pos < len && v[*pos] != ',') (*pos)++;
        size_t e = *pos;
        if (*pos < len) (*pos)++;                        /* skip ',' */
        const unsigned char *semi = memchr(v + s, ';', e - s);
        if (semi) e = (size_t)(semi - v);
        while (s < e && is_ows(v[s])) s++;
        while (e > s && is_ows(v[e - 1])) e--;
        if (e > s) { *tok = v + s; *tok_len = e - s; return 1; }
    }
    return 0;
}

/* ======================================================================== */
/* Request head                                                             */
/* ======================================================================== */

/* Bounds-checked append to the rebuilt request head. */
#define OUT_APPEND(data, len) do {                                          \
        size_t _l = (len);                                                  \
        if (olen + _l > sizeof(rw->out)) return fail(rw, PQ_RW_TOO_LARGE);  \
        memcpy(o + olen, (data), _l);                                       \
        olen += _l;                                                         \
    } while (0)

static int process_head(pq_http_rewriter_t *rw, pq_rw_emit_fn emit, void *ctx) {
    const unsigned char *h = rw->head;
    size_t n = rw->head_len;                 /* ends with CRLF CRLF */
    unsigned char *o = rw->out;
    size_t olen = 0;

    /* ---- request-line: method SP request-target SP HTTP-version ---- */
    const unsigned char *lf = memchr(h, '\n', n);
    size_t rl_len = (size_t)(lf - h) - 1;
    if (memchr(h, '\r', rl_len)) return fail(rw, PQ_RW_BAD_REQUEST);

    size_t i = 0;
    while (i < rl_len && is_tchar(h[i])) i++;
    size_t method_len = i;
    if (method_len == 0 || method_len > 32 || i >= rl_len || h[i] != ' ')
        return fail(rw, PQ_RW_BAD_REQUEST);
    size_t t0 = ++i;
    while (i < rl_len && h[i] > 0x20 && h[i] != 0x7f) i++;
    size_t target_len = i - t0;
    if (target_len == 0 || i >= rl_len || h[i] != ' ')
        return fail(rw, PQ_RW_BAD_REQUEST);
    const unsigned char *ver = h + i + 1;
    size_t ver_len = rl_len - i - 1;

    int v11;
    if (ver_len == 8 && memcmp(ver, "HTTP/1.1", 8) == 0) {
        v11 = 1;
    } else if (ver_len == 8 && memcmp(ver, "HTTP/1.0", 8) == 0) {
        v11 = 0;
    } else if (rw->first && ver_len == 8 && memcmp(ver, "HTTP/2.0", 8) == 0 &&
               method_len == 3 && memcmp(h, "PRI", 3) == 0 &&
               target_len == 1 && h[t0] == '*') {
        /* h2c prior-knowledge preface: relay the connection untouched */
        rw->first = 0;
        rw->st = ST_PASSTHROUGH;
        return emit_or_fail(rw, emit, ctx, h, n);
    } else {
        return fail(rw, PQ_RW_BAD_REQUEST);
    }
    rw->first = 0;

    int is_connect = (method_len == 7 && memcmp(h, "CONNECT", 7) == 0);

    OUT_APPEND(h, rl_len + 2);

    /* ---- header fields ---- */
    int host_count = 0, has_cl = 0, has_te = 0;
    int chunked_count = 0, last_chunked = 0;
    int has_upgrade = 0, conn_upgrade = 0;
    uint64_t cl = 0;

    size_t pos = rl_len + 2;
    for (;;) {
        const unsigned char *e = memchr(h + pos, '\n', n - pos);
        size_t line_end = (size_t)(e - h) - 1;          /* index of '\r' */
        if (line_end == pos) break;                     /* empty line */
        const unsigned char *line = h + pos;
        size_t llen = line_end - pos;
        size_t v0, v1;
        size_t nlen = parse_field_line(line, llen, &v0, &v1);
        if (nlen == 0) return fail(rw, PQ_RW_BAD_REQUEST);
        const unsigned char *val = line + v0;
        size_t vlen = v1 - v0;
        pos = line_end + 2;

        if (is_managed_header(line, nlen)) continue;

        if (name_eq(line, nlen, "host")) {
            host_count++;
        } else if (name_eq(line, nlen, "content-length")) {
            if (vlen == 0 || vlen > 19) return fail(rw, PQ_RW_BAD_REQUEST);
            uint64_t v = 0;
            for (size_t k = 0; k < vlen; k++) {
                if (val[k] < '0' || val[k] > '9') return fail(rw, PQ_RW_BAD_REQUEST);
                v = v * 10 + (uint64_t)(val[k] - '0');
            }
            if (has_cl) {
                if (v != cl) return fail(rw, PQ_RW_BAD_REQUEST);
                continue;                               /* drop identical duplicate */
            }
            has_cl = 1;
            cl = v;
        } else if (name_eq(line, nlen, "transfer-encoding")) {
            has_te = 1;
            size_t p = 0;
            const unsigned char *tok;
            size_t tlen;
            while (next_list_elem(val, vlen, &p, &tok, &tlen)) {
                last_chunked = (tlen == 7 && strncasecmp((const char *)tok, "chunked", 7) == 0);
                if (last_chunked) chunked_count++;
            }
        } else if (name_eq(line, nlen, "upgrade")) {
            has_upgrade = 1;
        } else if (name_eq(line, nlen, "connection")) {
            /* Drop connection options that name proxy-owned headers, so an
             * intermediary cannot be told to strip them as hop-by-hop. */
            size_t start = olen;
            OUT_APPEND("Connection: ", 12);
            size_t first_tok = olen;
            size_t p = 0;
            const unsigned char *tok;
            size_t tlen;
            while (next_list_elem(val, vlen, &p, &tok, &tlen)) {
                if (is_managed_header(tok, tlen)) continue;
                if (name_eq(tok, tlen, "upgrade")) conn_upgrade = 1;
                if (olen > first_tok) OUT_APPEND(",", 1);
                OUT_APPEND(tok, tlen);
            }
            if (olen == first_tok) {
                olen = start;                           /* nothing left */
            } else {
                OUT_APPEND("\r\n", 2);
            }
            continue;
        }

        OUT_APPEND(line, llen + 2);                     /* incl. CRLF */
    }

    /* ---- framing decisions (RFC 9112 §3.2, §6.1, §6.3) ---- */
    if (host_count > 1 || (v11 && host_count == 0))
        return fail(rw, PQ_RW_BAD_REQUEST);
    if (has_te && has_cl) return fail(rw, PQ_RW_BAD_REQUEST);
    if (has_te && (!v11 || !last_chunked || chunked_count != 1))
        return fail(rw, PQ_RW_BAD_REQUEST);

    OUT_APPEND(rw->inject, rw->inject_len);
    OUT_APPEND("\r\n", 2);

    int rc = emit_or_fail(rw, emit, ctx, o, olen);
    if (rc != PQ_RW_OK) return rc;
    rw->requests++;

    rw->await_after_body = is_connect || (has_upgrade && conn_upgrade);
    rw->await_connect = is_connect;

    if (has_te) {
        rw->line_len = 0;
        rw->st = ST_CHUNK_SIZE;
    } else if (has_cl && cl > 0) {
        rw->remaining = cl;
        rw->st = ST_BODY;
    } else {
        finish_request(rw);
    }
    return PQ_RW_OK;
}

#undef OUT_APPEND

/* ======================================================================== */
/* Chunked body                                                             */
/* ======================================================================== */

static int process_chunk_size_line(pq_http_rewriter_t *rw, pq_rw_emit_fn emit, void *ctx) {
    const unsigned char *l = rw->line;
    size_t len = rw->line_len - 2;                      /* without CRLF */
    if (memchr(l, '\r', len)) return fail(rw, PQ_RW_BAD_REQUEST);

    uint64_t size = 0;
    size_t k = 0;
    int hv;
    while (k < len && (hv = hexval(l[k])) >= 0) {
        if (k >= 16) return fail(rw, PQ_RW_BAD_REQUEST);
        size = (size << 4) | (uint64_t)hv;
        k++;
    }
    if (k == 0) return fail(rw, PQ_RW_BAD_REQUEST);
    if (k < len) {
        size_t j = k;
        while (j < len && is_ows(l[j])) j++;            /* BWS */
        if (j >= len || l[j] != ';') return fail(rw, PQ_RW_BAD_REQUEST);
        for (; j < len; j++) {
            if (!is_field_char(l[j])) return fail(rw, PQ_RW_BAD_REQUEST);
        }
    }

    int rc = emit_or_fail(rw, emit, ctx, rw->line, rw->line_len);
    if (rc != PQ_RW_OK) return rc;
    rw->line_len = 0;
    if (size == 0) {
        rw->trailer_bytes = 0;
        rw->st = ST_TRAILER;
    } else {
        rw->remaining = size;
        rw->st = ST_CHUNK_DATA;
    }
    return PQ_RW_OK;
}

static int process_trailer_line(pq_http_rewriter_t *rw, pq_rw_emit_fn emit, void *ctx) {
    rw->trailer_bytes += rw->line_len;
    if (rw->trailer_bytes > PQ_RW_MAX_HEAD) return fail(rw, PQ_RW_TOO_LARGE);

    if (rw->line_len == 2) {                            /* end of trailer section */
        int rc = emit_or_fail(rw, emit, ctx, "\r\n", 2);
        if (rc != PQ_RW_OK) return rc;
        finish_request(rw);
        return PQ_RW_OK;
    }
    size_t v0, v1;
    size_t nlen = parse_field_line(rw->line, rw->line_len - 2, &v0, &v1);
    if (nlen == 0) return fail(rw, PQ_RW_BAD_REQUEST);
    size_t len = rw->line_len;
    rw->line_len = 0;
    if (is_managed_header(rw->line, nlen)) return PQ_RW_OK;
    return emit_or_fail(rw, emit, ctx, rw->line, len);
}

/* Accumulate one CRLF-terminated line into rw->line. Returns 1 when a full
 * line is available, 0 if more input is needed, <0 on error. */
static int take_line(pq_http_rewriter_t *rw, const unsigned char *in, size_t len,
                     size_t *i) {
    const unsigned char *lf = memchr(in + *i, '\n', len - *i);
    size_t take = lf ? (size_t)(lf - (in + *i)) + 1 : len - *i;
    if (rw->line_len + take > sizeof(rw->line)) return -1;
    memcpy(rw->line + rw->line_len, in + *i, take);
    rw->line_len += take;
    *i += take;
    if (!lf) return 0;
    if (rw->line_len < 2 || rw->line[rw->line_len - 2] != '\r') return -1;
    return 1;
}

/* ======================================================================== */
/* Public API                                                               */
/* ======================================================================== */

pq_http_rewriter_t *pq_http_rewriter_new(const char *inject) {
    size_t ilen = inject ? strlen(inject) : 0;
    if (ilen >= PQ_RW_MAX_INJECT) return NULL;
    pq_http_rewriter_t *rw = calloc(1, sizeof(*rw));
    if (!rw) return NULL;
    rw->st = ST_HEAD;
    rw->first = 1;
    if (ilen) memcpy(rw->inject, inject, ilen);
    rw->inject_len = ilen;
    return rw;
}

void pq_http_rewriter_free(pq_http_rewriter_t *rw) {
    if (!rw) return;
    free(rw->pending);
    free(rw);
}

int pq_http_rewriter_feed(pq_http_rewriter_t *rw, const unsigned char *in,
                          size_t len, pq_rw_emit_fn emit, void *ctx) {
    if (!rw || !emit) return PQ_RW_EMIT_FAILED;
    if (rw->st == ST_ERROR) return rw->err;

    size_t i = 0;
    while (i < len) {
        int rc;
        switch (rw->st) {
        case ST_PASSTHROUGH:
            return emit_or_fail(rw, emit, ctx, in + i, len - i);

        case ST_AWAIT: {
            size_t n = len - i;
            if (rw->pending_len + n > PQ_RW_MAX_HEAD) return fail(rw, PQ_RW_TOO_LARGE);
            if (!rw->pending) {
                rw->pending = malloc(PQ_RW_MAX_HEAD);
                if (!rw->pending) return fail(rw, PQ_RW_EMIT_FAILED);
            }
            memcpy(rw->pending + rw->pending_len, in + i, n);
            rw->pending_len += n;
            return PQ_RW_OK;
        }

        case ST_HEAD: {
            if (rw->head_len == 0) {
                /* RFC 9112 §2.2: ignore empty lines before a request-line */
                while (i < len && (in[i] == '\r' || in[i] == '\n')) i++;
                if (i == len) return PQ_RW_OK;
                /* Not HTTP at all (binary protocol): relay untouched. */
                if (rw->first && !is_tchar(in[i])) {
                    rw->st = ST_PASSTHROUGH;
                    continue;
                }
            }
            size_t old = rw->head_len;
            size_t room = PQ_RW_MAX_HEAD - old;
            size_t take = (len - i < room) ? len - i : room;
            memcpy(rw->head + old, in + i, take);

            size_t term = 0;
            for (size_t k = old; k < old + take; k++) {
                if (rw->head[k] != '\n') continue;
                if (k == 0 || rw->head[k - 1] != '\r') return fail(rw, PQ_RW_BAD_REQUEST);
                if (k >= 3 && rw->head[k - 2] == '\n' && rw->head[k - 3] == '\r') {
                    term = k + 1;
                    break;
                }
            }
            if (!term) {
                rw->head_len = old + take;
                i += take;
                if (rw->head_len >= PQ_RW_MAX_HEAD) return fail(rw, PQ_RW_TOO_LARGE);
                continue;
            }
            rw->head_len = term;
            i += term - old;
            rc = process_head(rw, emit, ctx);
            if (rc != PQ_RW_OK) return rc;
            continue;
        }

        case ST_BODY:
        case ST_CHUNK_DATA: {
            size_t n = len - i;
            if ((uint64_t)n > rw->remaining) n = (size_t)rw->remaining;
            rc = emit_or_fail(rw, emit, ctx, in + i, n);
            if (rc != PQ_RW_OK) return rc;
            i += n;
            rw->remaining -= n;
            if (rw->remaining == 0) {
                if (rw->st == ST_BODY) {
                    finish_request(rw);
                } else {
                    rw->crlf_pos = 0;
                    rw->st = ST_CHUNK_CRLF;
                }
            }
            continue;
        }

        case ST_CHUNK_CRLF: {
            unsigned char c = in[i++];
            if (rw->crlf_pos == 0) {
                if (c != '\r') return fail(rw, PQ_RW_BAD_REQUEST);
                rw->crlf_pos = 1;
            } else {
                if (c != '\n') return fail(rw, PQ_RW_BAD_REQUEST);
                rc = emit_or_fail(rw, emit, ctx, "\r\n", 2);
                if (rc != PQ_RW_OK) return rc;
                rw->line_len = 0;
                rw->st = ST_CHUNK_SIZE;
            }
            continue;
        }

        case ST_CHUNK_SIZE:
        case ST_TRAILER: {
            int got = take_line(rw, in, len, &i);
            if (got < 0) return fail(rw, PQ_RW_BAD_REQUEST);
            if (got == 0) continue;
            rc = (rw->st == ST_CHUNK_SIZE) ? process_chunk_size_line(rw, emit, ctx)
                                           : process_trailer_line(rw, emit, ctx);
            if (rc != PQ_RW_OK) return rc;
            continue;
        }

        case ST_ERROR:
        default:
            return rw->err ? rw->err : PQ_RW_BAD_REQUEST;
        }
    }
    return PQ_RW_OK;
}

int pq_http_rewriter_on_response(pq_http_rewriter_t *rw, const unsigned char *data,
                                 size_t len, pq_rw_emit_fn emit, void *ctx) {
    if (!rw || rw->st != ST_AWAIT) return PQ_RW_OK;

    size_t need = sizeof(rw->status) - rw->status_len;
    size_t take = len < need ? len : need;
    memcpy(rw->status + rw->status_len, data, take);
    rw->status_len += take;
    if (rw->status_len < sizeof(rw->status)) return PQ_RW_OK;

    /* "HTTP/1.x NNN" */
    const unsigned char *s = rw->status;
    int code = -1;
    if (memcmp(s, "HTTP/1.", 7) == 0 && s[8] == ' ' &&
        s[9] >= '0' && s[9] <= '9' && s[10] >= '0' && s[10] <= '9' &&
        s[11] >= '0' && s[11] <= '9') {
        code = (s[9] - '0') * 100 + (s[10] - '0') * 10 + (s[11] - '0');
    }
    int tunnel = rw->await_connect ? (code >= 200 && code < 300) : (code == 101);

    unsigned char *pend = rw->pending;
    size_t pend_len = rw->pending_len;
    rw->pending = NULL;
    rw->pending_len = 0;

    int rc = PQ_RW_OK;
    if (tunnel) {
        rw->st = ST_PASSTHROUGH;
        if (pend_len) rc = emit_or_fail(rw, emit, ctx, pend, pend_len);
    } else {
        rw->st = ST_HEAD;
        rw->head_len = 0;
        if (pend_len) rc = pq_http_rewriter_feed(rw, pend, pend_len, emit, ctx);
    }
    free(pend);
    return rc;
}

int pq_http_rewriter_in_head(const pq_http_rewriter_t *rw) {
    return rw && rw->st == ST_HEAD && rw->head_len > 0;
}

int pq_http_rewriter_awaiting_response(const pq_http_rewriter_t *rw) {
    return rw && rw->st == ST_AWAIT;
}

int pq_http_rewriter_is_passthrough(const pq_http_rewriter_t *rw) {
    return rw && rw->st == ST_PASSTHROUGH;
}

unsigned long pq_http_rewriter_request_count(const pq_http_rewriter_t *rw) {
    return rw ? rw->requests : 0;
}

static void sanitize_value(char *dst, size_t dst_len, const char *src) {
    size_t j = 0;
    if (!src || !*src) src = "unknown";
    for (size_t i = 0; src[i] && j + 1 < dst_len; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[j++] = (c >= 0x21 && c <= 0x7e) ? (char)c : '_';
    }
    dst[j] = '\0';
}

int pq_http_render_forward_headers(char *out, size_t out_len,
                                   const char *client_ip, const char *group,
                                   const char *cipher, int is_pq) {
    char ip[64], grp[128], ciph[128];
    sanitize_value(ip, sizeof(ip), client_ip);
    sanitize_value(grp, sizeof(grp), group);
    sanitize_value(ciph, sizeof(ciph), cipher);
    int n = snprintf(out, out_len,
                     "X-Forwarded-For: %s\r\n"
                     "X-Real-IP: %s\r\n"
                     "X-Forwarded-Proto: https\r\n"
                     "X-PQ-KEM: %s\r\n"
                     "X-PQ-Group: %s\r\n"
                     "X-PQ-Cipher: %s\r\n",
                     ip, ip, is_pq ? grp : "none", grp, ciph);
    if (n < 0 || (size_t)n >= out_len) return -1;
    return n;
}
