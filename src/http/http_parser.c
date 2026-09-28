/*
 * http_parser.c - HTTP/1.1 Incremental Parser Implementation
 */

#include "http_parser.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>

/* Parser states */
enum {
    PARSE_METHOD,
    PARSE_URI,
    PARSE_VERSION,
    PARSE_HEADER_LINE,
    PARSE_HEADER_VALUE,
    PARSE_DONE
};

void pq_http_request_init(pq_http_request_t *req)
{
    memset(req, 0, sizeof(*req));
    req->_state = PARSE_METHOD;
    req->content_length = -1;
    req->keep_alive = 1;  /* HTTP/1.1 default */
    req->version_major = 1;
    req->version_minor = 1;
}

void pq_http_request_reset(pq_http_request_t *req)
{
    memset(req, 0, sizeof(*req));
    req->_state = PARSE_METHOD;
    req->content_length = -1;
    req->keep_alive = 1;
    req->version_major = 1;
    req->version_minor = 1;
}

const char* pq_http_method_str(pq_http_method_t m)
{
    switch (m) {
        case HTTP_METHOD_GET:     return "GET";
        case HTTP_METHOD_POST:    return "POST";
        case HTTP_METHOD_PUT:     return "PUT";
        case HTTP_METHOD_DELETE:  return "DELETE";
        case HTTP_METHOD_PATCH:   return "PATCH";
        case HTTP_METHOD_HEAD:    return "HEAD";
        case HTTP_METHOD_OPTIONS: return "OPTIONS";
        case HTTP_METHOD_CONNECT: return "CONNECT";
        case HTTP_METHOD_UNKNOWN: return "UNKNOWN";
        default:                  return "UNKNOWN";
    }
}

static pq_http_method_t parse_method_string(const char *str, size_t len)
{
    if (len == 3 && strncmp(str, "GET", 3) == 0)
        return HTTP_METHOD_GET;
    if (len == 4 && strncmp(str, "POST", 4) == 0)
        return HTTP_METHOD_POST;
    if (len == 3 && strncmp(str, "PUT", 3) == 0)
        return HTTP_METHOD_PUT;
    if (len == 6 && strncmp(str, "DELETE", 6) == 0)
        return HTTP_METHOD_DELETE;
    if (len == 5 && strncmp(str, "PATCH", 5) == 0)
        return HTTP_METHOD_PATCH;
    if (len == 4 && strncmp(str, "HEAD", 4) == 0)
        return HTTP_METHOD_HEAD;
    if (len == 7 && strncmp(str, "OPTIONS", 7) == 0)
        return HTTP_METHOD_OPTIONS;
    if (len == 7 && strncmp(str, "CONNECT", 7) == 0)
        return HTTP_METHOD_CONNECT;
    return HTTP_METHOD_UNKNOWN;
}

/* Find \r\n\r\n in buffer, indicating end of headers */
static int find_header_end(const char *buf, size_t len, size_t *offset) {
    if (len < 4) return 0;

    /* Single-pass scanner: look for \r\n\r\n pattern */
    const char *p = buf;
    const char *end = buf + len - 3;

    while (p <= end) {
        p = (const char *)memchr(p, '\r', (size_t)(end - p) + 1);
        if (!p) return 0;
        if (p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
            *offset = (size_t)(p - buf);
            return 1;
        }
        p++;
    }
    return 0;
}

/* RFC 9110 5.6.2: tchar (ASCII only, locale independent) */
static int is_tchar(unsigned char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
    case '+': case '-': case '.': case '^': case '_': case '`': case '|':
    case '~':
        return 1;
    default:
        return 0;
    }
}

static int is_ows(unsigned char c)
{
    return c == ' ' || c == '\t';
}

/* RFC 9110 5.5: field-vchar / SP / HTAB (obs-text allowed); no CTLs */
static int is_field_value_char(unsigned char c)
{
    return c == '\t' || (c >= 0x20 && c != 0x7F);
}

/*
 * Content-Length = 1*DIGIT (RFC 9110 8.6). No sign, no whitespace, no
 * list form, no overflow. Returns 0 on success, -1 if invalid.
 */
static int parse_content_length(const char *v, int64_t *out)
{
    if (*v == '\0')
        return -1;

    int64_t n = 0;
    for (; *v; v++) {
        unsigned char c = (unsigned char)*v;
        if (c < '0' || c > '9')
            return -1;
        int d = c - '0';
        if (n > (INT64_MAX - d) / 10)
            return -1;
        n = n * 10 + d;
    }
    *out = n;
    return 0;
}

/*
 * Parse a single "name: value" field line (without its CRLF).
 * Returns 1 on success, 0 if the line is malformed.
 */
static int parse_header_pair(const char *line, size_t len,
                             char *name, size_t name_len,
                             char *value, size_t value_len)
{
    /* field-name = token, immediately followed by ':' (RFC 9112 5.1:
     * no whitespace allowed between field name and colon) */
    size_t name_size = 0;
    while (name_size < len && is_tchar((unsigned char)line[name_size]))
        name_size++;

    if (name_size == 0 || name_size >= len || line[name_size] != ':')
        return 0;
    if (name_size >= name_len)
        return 0;

    memcpy(name, line, name_size);
    name[name_size] = '\0';

    /* Skip colon and leading OWS */
    const char *val_start = line + name_size + 1;
    const char *line_end = line + len;
    while (val_start < line_end && is_ows((unsigned char)*val_start))
        val_start++;

    /* Trim trailing OWS */
    const char *val_end = line_end;
    while (val_end > val_start && is_ows((unsigned char)*(val_end - 1)))
        val_end--;

    for (const char *c = val_start; c < val_end; c++) {
        if (!is_field_value_char((unsigned char)*c))
            return 0;
    }

    size_t val_len = (size_t)(val_end - val_start);
    if (val_len >= value_len)
        return 0;

    memcpy(value, val_start, val_len);
    value[val_len] = '\0';

    return 1;
}

/* Parse "HTTP/<d>.<d>" (exactly 8 octets) */
static int parse_version(const char *v, size_t len, int *major, int *minor)
{
    if (len != 8 || memcmp(v, "HTTP/", 5) != 0)
        return 0;
    if (v[5] < '0' || v[5] > '9' || v[6] != '.' || v[7] < '0' || v[7] > '9')
        return 0;
    *major = v[5] - '0';
    *minor = v[7] - '0';
    return 1;
}

/* Parse request line and headers from accumulated buffer */
static __attribute__((hot))
pq_http_parse_status_t parse_headers(pq_http_request_t *req)
{
    size_t header_end = 0;
    if (!find_header_end(req->_buf, req->_buf_len, &header_end))
        return HTTP_PARSE_INCOMPLETE;

    /* Parsing is idempotent: reset everything derived from the headers */
    req->header_count = 0;
    req->content_length = -1;
    req->chunked = 0;
    req->keep_alive = 1;
    req->host = NULL;

    /* Headers are from start to header_end, body starts at header_end + 4 */
    req->_body_offset = header_end + 4;

    /*
     * The head (request line + field lines) is buf[0 .. header_end + 2):
     * every line is terminated by CRLF. Reject bare CR, bare LF and NUL
     * anywhere in it, so every line boundary is unambiguous (RFC 9112 2.2).
     */
    const char *buf = req->_buf;
    const char *head_end = buf + header_end + 2;
    for (const char *c = buf; c < head_end; c++) {
        if (*c == '\0')
            return HTTP_PARSE_ERROR;
        if (*c == '\r' && c[1] != '\n')
            return HTTP_PARSE_ERROR;
        if (*c == '\n' && (c == buf || c[-1] != '\r'))
            return HTTP_PARSE_ERROR;
    }

    /* ---- Request line: method SP request-target SP HTTP-version ---- */
    const char *line_start = buf;
    const char *line_end = memchr(line_start, '\r', (size_t)(head_end - line_start));
    if (!line_end)
        return HTTP_PARSE_ERROR;

    size_t line_len = (size_t)(line_end - line_start);
    if (line_len == 0)
        return HTTP_PARSE_ERROR;

    const char *space1 = memchr(line_start, ' ', line_len);
    if (!space1 || space1 == line_start)
        return HTTP_PARSE_ERROR;

    size_t method_len = (size_t)(space1 - line_start);
    for (size_t i = 0; i < method_len; i++) {
        if (!is_tchar((unsigned char)line_start[i]))
            return HTTP_PARSE_ERROR;
    }
    req->method = parse_method_string(line_start, method_len);

    const char *uri_start = space1 + 1;
    const char *space2 = memchr(uri_start, ' ', (size_t)(line_end - uri_start));
    if (!space2)
        return HTTP_PARSE_ERROR;

    size_t uri_len = (size_t)(space2 - uri_start);
    /* Enforce strict URI length limit to prevent buffer issues and DoS */
    if (uri_len == 0 || uri_len >= PQ_HTTP_MAX_URI_LEN)
        return HTTP_PARSE_ERROR;
    for (size_t i = 0; i < uri_len; i++) {
        unsigned char c = (unsigned char)uri_start[i];
        if (c <= 0x20 || c == 0x7F)
            return HTTP_PARSE_ERROR;
    }

    memcpy(req->uri, uri_start, uri_len);
    req->uri[uri_len] = '\0';

    /* Parse HTTP version */
    const char *version_str = space2 + 1;
    size_t version_len = (size_t)(line_end - version_str);
    if (!parse_version(version_str, version_len, &req->version_major, &req->version_minor))
        return HTTP_PARSE_ERROR;

    if (req->version_major != 1)
        return HTTP_PARSE_ERROR;

    /* HTTP/1.0 defaults to Connection: close */
    if (req->version_minor == 0)
        req->keep_alive = 0;

    /* ---- Field lines ---- */
    line_start = line_end + 2;  /* Skip \r\n */

    /* Track framing headers to detect request smuggling attempts. */
    int has_content_length = 0;
    int has_transfer_encoding = 0;

    while (line_start < head_end) {
        line_end = memchr(line_start, '\r', (size_t)(head_end - line_start));
        if (!line_end)
            return HTTP_PARSE_ERROR;

        line_len = (size_t)(line_end - line_start);
        if (line_len == 0)
            break;              /* cannot happen: first CRLFCRLF is head end */

        /* obs-fold (RFC 9112 5.2): a line starting with SP/HTAB is rejected */
        if (is_ows((unsigned char)line_start[0]))
            return HTTP_PARSE_ERROR;

        if (req->header_count >= PQ_HTTP_MAX_HEADERS)
            return HTTP_PARSE_ERROR;

        pq_http_header_t *h = &req->headers[req->header_count];
        if (!parse_header_pair(line_start, line_len,
                               h->name, sizeof(h->name),
                               h->value, sizeof(h->value)))
            return HTTP_PARSE_ERROR;

        const char *name = h->name;
        const char *value = h->value;

        if (strcasecmp(name, "Content-Length") == 0) {
            int64_t cl = 0;
            if (parse_content_length(value, &cl) < 0)
                return HTTP_PARSE_ERROR;
            /* Duplicates are only tolerated if identical (RFC 9110 8.6) */
            if (has_content_length && cl != req->content_length)
                return HTTP_PARSE_ERROR;
            has_content_length = 1;
            req->content_length = cl;
        } else if (strcasecmp(name, "Transfer-Encoding") == 0) {
            /* Only a single "chunked" coding is supported; anything else
             * (lists, other codings, repeated fields) is ambiguous framing. */
            if (has_transfer_encoding || strcasecmp(value, "chunked") != 0)
                return HTTP_PARSE_ERROR;
            has_transfer_encoding = 1;
            req->chunked = 1;
        } else if (strcasecmp(name, "Connection") == 0) {
            if (strcasecmp(value, "close") == 0)
                req->keep_alive = 0;
            else if (strcasecmp(value, "keep-alive") == 0)
                req->keep_alive = 1;
        } else if (strcasecmp(name, "Host") == 0) {
            /* RFC 9112 3.2: more than one Host field line -> 400 */
            if (req->host)
                return HTTP_PARSE_ERROR;
            req->host = value;
        }

        req->header_count++;
        line_start = line_end + 2;  /* Skip \r\n */
    }

    /* HTTP Request Smuggling Defense: Reject requests with both
       Content-Length and Transfer-Encoding headers present.
       This prevents ambiguity in body parsing and request smuggling attacks. */
    if (has_content_length && has_transfer_encoding)
        return HTTP_PARSE_ERROR;

    /* RFC 9112 6.1: Transfer-Encoding in an HTTP/1.0 request means faulty
       framing; reject rather than guess. */
    if (has_transfer_encoding && req->version_minor == 0)
        return HTTP_PARSE_ERROR;

    return HTTP_PARSE_COMPLETE;
}

__attribute__((hot))
pq_http_parse_status_t pq_http_request_parse(pq_http_request_t *req,
                                              const char *data,
                                              size_t len,
                                              size_t *consumed)
{
    if (!req || !data || !consumed)
        return HTTP_PARSE_ERROR;

    *consumed = 0;

    /* Headers already complete: body bytes are the caller's business */
    if (req->_state == PARSE_DONE)
        return HTTP_PARSE_COMPLETE;

    /* Append data to buffer */
    if (len > PQ_HTTP_MAX_HEADER_SIZE - req->_buf_len)
        return HTTP_PARSE_ERROR;  /* Header too large */

    memcpy(req->_buf + req->_buf_len, data, len);
    req->_buf_len += len;
    *consumed = len;

    /* Try to parse headers */
    pq_http_parse_status_t status = parse_headers(req);

    if (status == HTTP_PARSE_COMPLETE) {
        req->_state = PARSE_DONE;
        req->_header_bytes = req->_body_offset;
    }

    return status;
}

const char* pq_http_request_get_header(const pq_http_request_t *req, const char *name)
{
    if (!req || !name)
        return NULL;

    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].name, name) == 0)
            return req->headers[i].value;
    }

    return NULL;
}
