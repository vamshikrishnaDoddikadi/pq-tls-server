/**
 * @file http_rewriter.h
 * @brief Streaming HTTP/1.x request rewriter for the client -> backend path
 *
 * The TLS terminator is the trust boundary for everything the backend learns
 * about the client, so every request on a connection (not just the first) is
 * rewritten:
 *
 *   - Client-supplied X-Forwarded-For / X-Forwarded-Proto / X-Forwarded-Host /
 *     X-Forwarded-Port / X-Real-IP / Forwarded and all X-PQ-* headers are
 *     removed, and authoritative values are appended.
 *   - Message framing is tracked exactly (Content-Length and chunked), so
 *     bytes inside a request body are never mistaken for a new header block.
 *   - Ambiguous framing that enables request smuggling is rejected with 400:
 *     Content-Length together with Transfer-Encoding, conflicting
 *     Content-Length values, a transfer coding that does not end in chunked,
 *     whitespace before the colon, obs-fold, bare CR/LF, invalid chunk sizes.
 *   - Oversized request heads are rejected with 431.
 *
 * Connections that do not start with an HTTP/1.x request line, h2c prior
 * knowledge ("PRI * HTTP/2.0"), and successful Upgrade/CONNECT exchanges are
 * relayed byte-for-byte.
 *
 * @author Vamshi Krishna Doddikadi
 */

#ifndef PQ_HTTP_REWRITER_H
#define PQ_HTTP_REWRITER_H

#include <stddef.h>

/** Maximum size of a request head (request line + header fields). */
#define PQ_RW_MAX_HEAD      (32 * 1024)
/** Maximum size of the pre-rendered header block appended to each request. */
#define PQ_RW_MAX_INJECT    1024

typedef enum {
    PQ_RW_OK          = 0,
    PQ_RW_EMIT_FAILED = -1,   /**< emit callback reported an I/O error */
    PQ_RW_BAD_REQUEST = 400,  /**< malformed / ambiguous request         */
    PQ_RW_TOO_LARGE   = 431,  /**< request head exceeds PQ_RW_MAX_HEAD   */
} pq_rw_status_t;

/** Output callback: forward @p len bytes to the backend. Return 0 on success. */
typedef int (*pq_rw_emit_fn)(void *ctx, const void *data, size_t len);

typedef struct pq_http_rewriter pq_http_rewriter_t;

/**
 * Create a rewriter.
 * @param inject  header block appended to every request head, already
 *                rendered as "Name: value\r\n..." (see pq_http_render_forward_headers)
 * @return NULL on allocation failure or if @p inject is too large.
 */
pq_http_rewriter_t *pq_http_rewriter_new(const char *inject);
void pq_http_rewriter_free(pq_http_rewriter_t *rw);

/**
 * Feed bytes received from the client. Rewritten output is delivered through
 * @p emit. Returns a pq_rw_status_t; after any non-OK status the rewriter is
 * in a terminal error state and the connection must be closed.
 */
int pq_http_rewriter_feed(pq_http_rewriter_t *rw, const unsigned char *in,
                          size_t len, pq_rw_emit_fn emit, void *ctx);

/**
 * Inspect bytes the backend sent while an Upgrade/CONNECT request is
 * pending. A "101" (Upgrade) or "2xx" (CONNECT) status switches the
 * connection to byte-for-byte relaying; anything else resumes HTTP parsing.
 * Any client bytes buffered while waiting are then processed via @p emit.
 */
int pq_http_rewriter_on_response(pq_http_rewriter_t *rw, const unsigned char *data,
                                 size_t len, pq_rw_emit_fn emit, void *ctx);

/** 1 while a partial request head is buffered (used for header timeouts). */
int pq_http_rewriter_in_head(const pq_http_rewriter_t *rw);

/** 1 while waiting for the backend's answer to an Upgrade/CONNECT request;
 *  the caller should stop reading from the client until it arrives. */
int pq_http_rewriter_awaiting_response(const pq_http_rewriter_t *rw);

/** 1 once the connection is relayed byte-for-byte. */
int pq_http_rewriter_is_passthrough(const pq_http_rewriter_t *rw);

/** Number of complete request heads rewritten so far. */
unsigned long pq_http_rewriter_request_count(const pq_http_rewriter_t *rw);

/**
 * Render the authoritative forwarding headers for a connection into @p out:
 *   X-Forwarded-For, X-Real-IP, X-Forwarded-Proto: https,
 *   X-PQ-KEM, X-PQ-Group, X-PQ-Cipher
 * Characters outside visible ASCII are replaced, so values can never inject
 * additional header lines.
 * @return length written, or -1 if @p out is too small.
 */
int pq_http_render_forward_headers(char *out, size_t out_len,
                                   const char *client_ip, const char *group,
                                   const char *cipher, int is_pq);

#endif /* PQ_HTTP_REWRITER_H */
