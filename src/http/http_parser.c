/*
 * http_parser.c - HTTP/1.1 Incremental Parser Implementation
 */

#include "http_parser.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>
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
            *offset = p - buf;
            return 1;
        }
        p++;
    }
    return 0;
}

/* Parse a single header name:value pair */
static int parse_header_pair(char *line, size_t len,
                             char *name, size_t name_len,
                             char *value, size_t value_len)
{
    char *colon = memchr(line, ':', len);
    if (!colon)
        return 0;

    size_t name_size = colon - line;
    if (name_size >= name_len)
        return 0;

    memcpy(name, line, name_size);
    name[name_size] = '\0';

    /* Skip colon and leading whitespace */
    const char *val_start = colon + 1;
    while (val_start < line + len && isspace(*val_start))
        val_start++;

    /* Find end (before \r\n) */
    size_t val_len = 0;
    const char *val_end = val_start;
    while (val_end < line + len && *val_end != '\r' && *val_end != '\n')
        val_end++;

    /* Trim trailing whitespace */
    while (val_end > val_start && isspace(*(val_end - 1)))
        val_end--;

    val_len = val_end - val_start;
    if (val_len >= value_len)
        return 0;

    memcpy(value, val_start, val_len);
    value[val_len] = '\0';

    return 1;
}

/* Parse request line and headers from accumulated buffer */
static __attribute__((hot))
pq_http_parse_status_t parse_headers(pq_http_request_t *req)
{
    size_t header_end = 0;
    if (!find_header_end(req->_buf, req->_buf_len, &header_end))
        return HTTP_PARSE_INCOMPLETE;

    /* Headers are from start to header_end, body starts at header_end + 4 */
    req->_body_offset = header_end + 4;

    char *line_start = req->_buf;
    char *line_end;

    /* Parse request line */
    line_end = memchr(line_start, '\r', header_end - (line_start - req->_buf));
    if (!line_end)
        return HTTP_PARSE_ERROR;

    size_t line_len = line_end - line_start;
    if (line_len == 0)
        return HTTP_PARSE_ERROR;

    /* Extract method, uri, version from request line */
    char *space1 = memchr(line_start, ' ', line_len);
    if (!space1)
        return HTTP_PARSE_ERROR;

    size_t method_len = space1 - line_start;
    req->method = parse_method_string(line_start, method_len);

    char *space2 = memchr(space1 + 1, ' ', line_len - (space1 - line_start) - 1);
    if (!space2)
        return HTTP_PARSE_ERROR;

    size_t uri_len = space2 - (space1 + 1);
    /* Enforce strict URI length limit to prevent buffer issues and DoS */
    if (uri_len == 0 || uri_len >= PQ_HTTP_MAX_URI_LEN)
        return HTTP_PARSE_ERROR;

    memcpy(req->uri, space1 + 1, uri_len);
    req->uri[uri_len] = '\0';

    /* Parse HTTP version */
    const char *version_str = space2 + 1;
    size_t version_len = line_len - (space2 - line_start) - 1;

    if (version_len < 8 || strncmp(version_str, "HTTP/", 5) != 0)
        return HTTP_PARSE_ERROR;

    const char *dot = memchr(version_str, '.', version_len);
    if (!dot)
        return HTTP_PARSE_ERROR;

    req->version_major = atoi(version_str + 5);
    req->version_minor = atoi(dot + 1);

    if (req->version_major != 1)
        return HTTP_PARSE_ERROR;

    /* HTTP/1.0 defaults to Connection: close */
    if (req->version_minor == 0)
        req->keep_alive = 0;

    /* Parse headers */
    line_start = line_end + 2;  /* Skip \r\n */

    /* Track if we've seen both Content-Length and Transfer-Encoding
       to detect potential request smuggling attempts. */
    int has_content_length = 0;
    int has_transfer_encoding = 0;

    while (line_start < req->_buf + header_end) {
        /* Search up to and including header_end position for \r */
        /* Calculate bytes from line_start to buffer end, but cap at actual data */
        size_t bytes_to_end = (size_t)((req->_buf + header_end) - line_start) + 1;
        if (bytes_to_end > req->_buf_len) {
            return HTTP_PARSE_ERROR;  /* Safety check: data corruption */
        }
        line_end = memchr(line_start, '\r', bytes_to_end);
        if (!line_end)
            return HTTP_PARSE_ERROR;

        line_len = line_end - line_start;

        if (line_len == 0) {
            /* Empty line = end of headers */
            break;
        }

        if (req->header_count >= PQ_HTTP_MAX_HEADERS)
            return HTTP_PARSE_ERROR;

        if (!parse_header_pair(line_start, line_len,
                              req->headers[req->header_count].name, sizeof(req->headers[req->header_count].name),
                              req->headers[req->header_count].value, sizeof(req->headers[req->header_count].value)))
            return HTTP_PARSE_ERROR;

        /* Post-process important headers with fast path for common ones */
        const char *name = req->headers[req->header_count].name;
        const char *value = req->headers[req->header_count].value;

        /* Check important headers */
        if (strcasecmp(name, "Content-Length") == 0) {
            has_content_length = 1;
            req->content_length = strtoll(value, NULL, 10);
        } else if (strcasecmp(name, "Connection") == 0) {
            if (strcasecmp(value, "close") == 0)
                req->keep_alive = 0;
            else if (strcasecmp(value, "keep-alive") == 0)
                req->keep_alive = 1;
        } else if (strcasecmp(name, "Transfer-Encoding") == 0) {
            has_transfer_encoding = 1;
            if (strcasecmp(value, "chunked") == 0)
                req->chunked = 1;
        } else if (strcasecmp(name, "Host") == 0) {
            req->host = value;
        }

        req->header_count++;
        line_start = line_end + 2;  /* Skip \r\n */
    }

    /* HTTP Request Smuggling Defense: Reject requests with both
       Content-Length and Transfer-Encoding headers present.
       This prevents ambiguity in body parsing and request smuggling attacks. */
    if (has_content_length && has_transfer_encoding) {
        return HTTP_PARSE_ERROR;
    }

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

    /* Append data to buffer */
    if (req->_buf_len + len > PQ_HTTP_MAX_HEADER_SIZE)
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
