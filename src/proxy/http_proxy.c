/**
 * @file http_proxy.c
 * @brief Bidirectional TCP/HTTP proxy implementation
 */

#include "http_proxy.h"
#include "http_rewriter.h"

#include <openssl/err.h>
#include <limits.h>
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <syslog.h>

#define PROXY_BUF_SIZE  65536  /* holds several 16 KiB TLS records */
#define RELAY_TICK_MS   1000   /* granularity of timeout / shutdown checks */

/* ======================================================================== */
/* Connect to upstream                                                      */
/* ======================================================================== */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

int pq_proxy_connect_upstream(const char *host, uint16_t port, int timeout_ms) {
    /* Resolve hostname */
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0) {
        /* SECURITY: Log upstream connection failures for debugging */
        syslog(LOG_ERR, "proxy: getaddrinfo(%s:%s) failed: %s", host, port_str, gai_strerror(gai));
        fprintf(stderr, "proxy: getaddrinfo(%s:%s) failed: %s\n", host, port_str, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    int last_err = 0;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            last_err = errno;
            syslog(LOG_WARNING, "proxy: socket() for %s failed: %s", host, strerror(errno));
            continue;
        }

        /* Non-blocking connect with timeout */
        set_nonblocking(fd);
        int ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            /* Connected immediately */
            set_blocking(fd);
            break;
        }
        if (errno != EINPROGRESS) {
            last_err = errno;
            syslog(LOG_WARNING, "proxy: connect() to %s:%s failed: %s", host, port_str, strerror(errno));
            close(fd); fd = -1;
            continue;
        }

        /* Wait for connect to complete */
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) {
            last_err = (ret == 0) ? ETIMEDOUT : errno;
            syslog(LOG_WARNING, "proxy: poll() timeout connecting to %s:%s", host, port_str);
            close(fd); fd = -1;
            continue;
        }

        /* Check for connect errors */
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) {
            last_err = err;
            syslog(LOG_WARNING, "proxy: SO_ERROR=%d connecting to %s:%s: %s", err, host, port_str, strerror(err));
            close(fd); fd = -1;
            continue;
        }

        set_blocking(fd);
        break;
    }

    freeaddrinfo(res);

    if (fd >= 0) {
        int opt = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    } else {
        /* SECURITY: Log when all connection attempts fail */
        syslog(LOG_ERR, "proxy: all connect attempts to %s:%s failed (last error: %s)",
               host, port_str, strerror(last_err));
    }

    return fd;
}


/* ======================================================================== */
/* I/O helpers                                                              */
/* ======================================================================== */

static long elapsed_ms(const struct timespec *since) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(now.tv_sec - since->tv_sec) * 1000L +
           (long)(now.tv_nsec - since->tv_nsec) / 1000000L;
}

/* Write everything to a non-blocking socket; each stall may last at most
 * timeout_ms (a peer that stops reading cannot pin the thread forever). */
static int send_all(int fd, const void *data, size_t len, int timeout_ms) {
    const unsigned char *p = data;
    while (len > 0) {
        ssize_t w = send(fd, p, len, MSG_NOSIGNAL);
        if (w > 0) {
            p += w;
            len -= (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int r = poll(&pfd, 1, timeout_ms);
            if (r > 0 || (r < 0 && errno == EINTR)) continue;
            return -1;                                  /* timed out */
        }
        return -1;
    }
    return 0;
}

static int ssl_write_all(SSL *ssl, const void *data, size_t len, int timeout_ms) {
    const unsigned char *p = data;
    int fd = SSL_get_fd(ssl);
    while (len > 0) {
        int chunk = len > (size_t)INT_MAX ? INT_MAX : (int)len;
        int w = SSL_write(ssl, p, chunk);
        if (w > 0) {
            p += w;
            len -= (size_t)w;
            continue;
        }
        int e = SSL_get_error(ssl, w);
        short ev = (e == SSL_ERROR_WANT_WRITE) ? POLLOUT
                 : (e == SSL_ERROR_WANT_READ)  ? POLLIN : 0;
        if (!ev) { ERR_clear_error(); return -1; }
        struct pollfd pfd = { .fd = fd, .events = ev };
        int r = poll(&pfd, 1, timeout_ms);
        if (r > 0 || (r < 0 && errno == EINTR)) continue;
        return -1;
    }
    return 0;
}

void pq_proxy_send_status(SSL *ssl, int status, int timeout_ms) {
    const char *reason;
    switch (status) {
    case 400: reason = "Bad Request"; break;
    case 408: reason = "Request Timeout"; break;
    case 431: reason = "Request Header Fields Too Large"; break;
    case 502: reason = "Bad Gateway"; break;
    case 503: reason = "Service Unavailable"; break;
    default:  reason = "Error"; break;
    }
    char resp[256];
    int body_len = (int)strlen(reason) + 2;
    int n = snprintf(resp, sizeof(resp),
                     "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\n"
                     "Content-Length: %d\r\nConnection: close\r\n\r\n%s\r\n",
                     status, reason, body_len, reason);
    if (n > 0 && (size_t)n < sizeof(resp))
        (void)ssl_write_all(ssl, resp, (size_t)n, timeout_ms);
}

/* Buffered writer for rewritten client data (coalesces small pieces such
 * as chunk-size lines into few send() calls). */
typedef struct {
    int            fd;
    int            timeout_ms;
    unsigned char *buf;
    size_t         len;
    size_t         cap;
} backend_out_t;

static int out_flush(backend_out_t *o) {
    if (o->len == 0) return 0;
    int r = send_all(o->fd, o->buf, o->len, o->timeout_ms);
    o->len = 0;
    return r;
}

static int out_emit(void *ctx, const void *data, size_t len) {
    backend_out_t *o = ctx;
    if (o->len + len > o->cap) {
        if (out_flush(o) != 0) return -1;
        if (len > o->cap) return send_all(o->fd, data, len, o->timeout_ms);
    }
    memcpy(o->buf + o->len, data, len);
    o->len += len;
    return 0;
}

/* True if SSL_read's failure means the client finished sending (close_notify,
 * or a TCP FIN without one), as opposed to a protocol error. */
static int client_eof_error(int ssl_err) {
    if (ssl_err == SSL_ERROR_ZERO_RETURN) return 1;
    if (ssl_err == SSL_ERROR_SYSCALL && ERR_peek_error() == 0) return 1;
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    if (ssl_err == SSL_ERROR_SSL &&
        ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
        return 1;
#endif
    return 0;
}

/* ======================================================================== */
/* Bidirectional relay                                                      */
/* ======================================================================== */

pq_proxy_result_t pq_proxy_relay(SSL *ssl, int backend_fd, int idle_timeout_ms,
                                 const pq_proxy_info_t *info) {
    pq_proxy_result_t result = {0, 0, 0, 0, 0};
    const int client_fd = SSL_get_fd(ssl);
    const int tick = idle_timeout_ms < RELAY_TICK_MS ? idle_timeout_ms : RELAY_TICK_MS;

    unsigned char *buf  = malloc(PROXY_BUF_SIZE);
    unsigned char *obuf = malloc(PROXY_BUF_SIZE);
    pq_http_rewriter_t *rw = NULL;
    backend_out_t out = { backend_fd, idle_timeout_ms, obuf, 0, PROXY_BUF_SIZE };

    if (!buf || !obuf) { result.error = -1; goto done; }

    if (info && info->rewrite_http) {
        char inject[PQ_RW_MAX_INJECT];
        if (pq_http_render_forward_headers(inject, sizeof(inject), info->client_addr,
                                           info->group_name, info->cipher_name,
                                           info->is_pq) < 0 ||
            !(rw = pq_http_rewriter_new(inject))) {
            result.error = -1;
            goto done;
        }
    }

    set_nonblocking(backend_fd);

    struct timespec last_activity, head_started;
    clock_gettime(CLOCK_MONOTONIC, &last_activity);
    int in_head = 0;
    int client_eof = 0;

    for (;;) {
        if (info && info->force_stop && atomic_load(info->force_stop)) break;
        int draining = info && info->running && !atomic_load(info->running);

        int want_client = !client_eof && !(rw && pq_http_rewriter_awaiting_response(rw));
        int pending = want_client ? SSL_pending(ssl) : 0;

        struct pollfd fds[2];
        fds[0].fd = want_client ? client_fd : -1;   /* -1: not polled at all */
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = backend_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        int nready = 0;
        if (pending <= 0) {
            nready = poll(fds, 2, tick);
            if (nready < 0) {
                if (errno == EINTR) continue;
                result.error = -1;
                break;
            }
        }

        /* Slow request heads (slowloris) are bounded independently of the
         * idle timeout, which trickled bytes would keep resetting. */
        if (rw && info->header_timeout_ms > 0) {
            int now_in_head = pq_http_rewriter_in_head(rw);
            if (now_in_head && !in_head) clock_gettime(CLOCK_MONOTONIC, &head_started);
            in_head = now_in_head;
            if (in_head && elapsed_ms(&head_started) >= info->header_timeout_ms) {
                if (pq_http_rewriter_request_count(rw) == 0)
                    pq_proxy_send_status(ssl, 408, 1000);
                result.http_status = 408;
                result.error = -1;
                break;
            }
        }

        if (pending <= 0 && nready == 0) {
            if (draining) break;                         /* idle: safe to close */
            if (elapsed_ms(&last_activity) >= idle_timeout_ms) break;
            continue;
        }

        /* ---- client -> backend ---- */
        if (want_client && (pending > 0 || fds[0].revents)) {
            int n = SSL_read(ssl, buf, PROXY_BUF_SIZE);
            if (n > 0) {
                clock_gettime(CLOCK_MONOTONIC, &last_activity);
                result.bytes_from_client += (size_t)n;
                if (rw) {
                    int rc = pq_http_rewriter_feed(rw, buf, (size_t)n, out_emit, &out);
                    if (rc == PQ_RW_OK && out_flush(&out) != 0) rc = PQ_RW_EMIT_FAILED;
                    if (rc != PQ_RW_OK) {
                        if (rc == PQ_RW_BAD_REQUEST || rc == PQ_RW_TOO_LARGE) {
                            /* Only answer if no backend response can be in
                             * flight, or the reply would interleave with it. */
                            if (pq_http_rewriter_request_count(rw) == 0)
                                pq_proxy_send_status(ssl, rc, 1000);
                            result.http_status = rc;
                        }
                        result.error = -1;
                        break;
                    }
                } else if (send_all(backend_fd, buf, (size_t)n, idle_timeout_ms) != 0) {
                    result.error = -1;
                    break;
                }
            } else {
                int e = SSL_get_error(ssl, n);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    /* partial TLS record; poll again */
                } else if (client_eof_error(e)) {
                    /* Client finished sending: pass the half-close on and
                     * keep delivering the backend's response. */
                    client_eof = 1;
                    shutdown(backend_fd, SHUT_WR);
                } else {
                    ERR_clear_error();
                    result.error = -1;
                    break;
                }
                ERR_clear_error();
            }
        }

        /* ---- backend -> client ---- */
        if (fds[1].revents) {
            ssize_t n = recv(backend_fd, buf, PROXY_BUF_SIZE, 0);
            if (n > 0) {
                clock_gettime(CLOCK_MONOTONIC, &last_activity);
                result.bytes_from_backend += (size_t)n;
                if (ssl_write_all(ssl, buf, (size_t)n, idle_timeout_ms) != 0) {
                    result.error = -1;
                    break;
                }
                if (rw && pq_http_rewriter_awaiting_response(rw)) {
                    int rc = pq_http_rewriter_on_response(rw, buf, (size_t)n, out_emit, &out);
                    if (rc == PQ_RW_OK && out_flush(&out) != 0) rc = PQ_RW_EMIT_FAILED;
                    if (rc != PQ_RW_OK) {
                        if (rc == PQ_RW_BAD_REQUEST || rc == PQ_RW_TOO_LARGE)
                            result.http_status = rc;
                        result.error = -1;
                        break;
                    }
                }
            } else if (n == 0) {
                break;                                   /* backend closed */
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                result.error = -1;
                break;
            }
        }
    }

done:
    if (rw) {
        result.requests = pq_http_rewriter_request_count(rw);
        pq_http_rewriter_free(rw);
    }
    free(buf);
    free(obuf);
    return result;
}
