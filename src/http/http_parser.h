/*
 * http_parser.h - HTTP/1.1 Incremental Parser
 *
 * Implements an incremental state machine for parsing HTTP/1.1 requests.
 * Parses request line and headers; body handling delegated to caller.
 * Suitable for non-blocking I/O where data arrives in chunks.
 */

#ifndef PQ_HTTP_PARSER_H
#define PQ_HTTP_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_UNKNOWN
} pq_http_method_t;

typedef enum {
    HTTP_PARSE_INCOMPLETE,   /* Need more data */
    HTTP_PARSE_COMPLETE,     /* Headers fully parsed */
    HTTP_PARSE_ERROR         /* Malformed request */
} pq_http_parse_status_t;

#define PQ_HTTP_MAX_HEADERS    64
#define PQ_HTTP_MAX_HEADER_SIZE 8192
#define PQ_HTTP_MAX_URI_LEN    4096

typedef struct {
    char name[128];
    char value[4096];
} pq_http_header_t;

typedef struct {
    /* Request line */
    pq_http_method_t method;
    char             uri[PQ_HTTP_MAX_URI_LEN];
    int              version_major;   /* 1 */
    int              version_minor;   /* 0 or 1 */

    /* Headers */
    pq_http_header_t headers[PQ_HTTP_MAX_HEADERS];
    int              header_count;

    /* Parsed from headers */
    int64_t          content_length;  /* -1 if not present */
    int              keep_alive;      /* 1 for HTTP/1.1 default, 0 if "Connection: close" */
    int              chunked;         /* Transfer-Encoding: chunked */
    const char      *host;           /* pointer into headers array */

    /* Parser state (internal) */
    int              _state;
    size_t           _header_bytes;   /* Total header bytes consumed */
    char             _buf[PQ_HTTP_MAX_HEADER_SIZE];
    size_t           _buf_len;
    size_t           _body_offset;    /* Offset into _buf where body starts */
} pq_http_request_t;

/*
 * Initialize a request structure.
 */
void pq_http_request_init(pq_http_request_t *req);

/*
 * Parse incremental data. Feed chunks of incoming data.
 *
 * Returns:
 *   HTTP_PARSE_INCOMPLETE - Need more data
 *   HTTP_PARSE_COMPLETE   - Headers fully parsed, body (if any) starts at req->_body_offset
 *   HTTP_PARSE_ERROR      - Malformed request
 *
 * consumed: (output) number of bytes consumed from data buffer
 */
pq_http_parse_status_t pq_http_request_parse(pq_http_request_t *req,
                                              const char *data,
                                              size_t len,
                                              size_t *consumed);

/*
 * Case-insensitive header lookup.
 * Returns pointer to header value, or NULL if not found.
 */
const char* pq_http_request_get_header(const pq_http_request_t *req, const char *name);

/*
 * Convert method enum to string.
 */
const char* pq_http_method_str(pq_http_method_t m);

/*
 * Reset request for next request on keep-alive connection.
 */
void pq_http_request_reset(pq_http_request_t *req);

#endif /* PQ_HTTP_PARSER_H */
