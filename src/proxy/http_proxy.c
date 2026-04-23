/**
 * @file http_proxy.c
 * @brief Bidirectional TCP/HTTP proxy implementation
 */

#include "http_proxy.h"

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

#define PROXY_BUF_SIZE  65536  /* Increased for efficient TLS record batching (16KB records + overhead) */

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
/* Bidirectional relay                                                      */
/* ======================================================================== */

/**
 * Inject PQ headers before the end of the first HTTP request's header block.
 * Searches for "\r\n\r\n" in buf[0..n), inserts headers before it, and sends
 * the modified request to backend_fd.  Returns total bytes sent, or -1 on error.
 */
static ssize_t inject_pq_headers(int backend_fd, unsigned char *buf, int n,
                                 const pq_proxy_info_t *info, int timeout_ms) {
    /* Find end-of-headers marker */
    unsigned char *eoh = NULL;
    for (int i = 0; i <= n - 4; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n') {
            eoh = buf + i;
            break;
        }
    }

    if (!eoh) {
        /* No complete headers yet — send as-is (unlikely for first read) */
        ssize_t sent = 0;
        while (sent < n) {
            ssize_t w = send(backend_fd, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
            if (w < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd wfd = { .fd = backend_fd, .events = POLLOUT };
                    poll(&wfd, 1, timeout_ms);
                    continue;
                }
                return -1;
            }
            sent += w;
        }
        return sent;
    }

    /* Build injection string */
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "\r\nX-PQ-KEM: %s\r\nX-PQ-Cipher: %s\r\nX-PQ-Group: %s",
        info->is_pq ? info->group_name : "none",
        info->cipher_name ? info->cipher_name : "unknown",
        info->group_name ? info->group_name : "unknown");
    if (hlen < 0 || hlen >= (int)sizeof(hdr)) hlen = 0;

    /* Send: [headers before \r\n\r\n] + injected headers + [\r\n\r\n + body] */
    struct iovec iov[3];
    iov[0].iov_base = buf;
    iov[0].iov_len  = (size_t)(eoh - buf);        /* up to \r\n\r\n */
    iov[1].iov_base = hdr;
    iov[1].iov_len  = (size_t)hlen;               /* injected headers */
    iov[2].iov_base = eoh;
    iov[2].iov_len  = (size_t)(n - (eoh - buf));   /* \r\n\r\n + body */

    size_t total = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;
    ssize_t sent = 0;

    /* Flatten and send (writev may partial-write) */
    for (int i = 0; i < 3; i++) {
        unsigned char *p = iov[i].iov_base;
        size_t rem = iov[i].iov_len;
        while (rem > 0) {
            ssize_t w = send(backend_fd, p, rem, MSG_NOSIGNAL);
            if (w < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct pollfd wfd = { .fd = backend_fd, .events = POLLOUT };
                    poll(&wfd, 1, timeout_ms);
                    continue;
                }
                return -1;
            }
            p += w;
            rem -= (size_t)w;
            sent += w;
        }
    }

    (void)total;
    return sent;
}

__attribute__((hot))
pq_proxy_result_t pq_proxy_relay(SSL *ssl, int backend_fd, int timeout_ms,
                                 const pq_proxy_info_t *pq_info) {
    pq_proxy_result_t result = {0, 0, 0};
    unsigned char buf[PROXY_BUF_SIZE];
    int ssl_fd = SSL_get_fd(ssl);
    int first_request = (pq_info != NULL) ? 1 : 0;

    /* Make backend non-blocking for poll */
    set_nonblocking(backend_fd);

    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = ssl_fd;
        fds[0].events = POLLIN;
        fds[1].fd = backend_fd;
        fds[1].events = POLLIN;

        /* Check if SSL has pending buffered data (optimized check) */
        int ssl_pending = SSL_pending(ssl);

        int nready;
        if (__builtin_expect(ssl_pending > 0, 0)) {
            /* Fast path: SSL has buffered data, process without poll */
            nready = 1;
            fds[0].revents = POLLIN;
            fds[1].revents = 0;
        } else {
            nready = poll(fds, 2, timeout_ms);
        }

        if (__builtin_expect(nready == 0, 0)) {
            /* Timeout — inactivity */
            result.error = 0;
            break;
        }
        if (__builtin_expect(nready < 0, 0)) {
            if (errno == EINTR) continue;
            result.error = -1;
            break;
        }

        /* Client -> Backend */
        if (ssl_pending > 0 || (fds[0].revents & POLLIN)) {
            int n = SSL_read(ssl, buf, sizeof(buf));
            if (__builtin_expect(n <= 0, 0)) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                /* Client closed or error */
                break;
            }
            result.bytes_from_client += (size_t)n;

            /* Inject PQ headers into the first HTTP request */
            if (__builtin_expect(first_request, 0)) {
                first_request = 0;
                ssize_t sent = inject_pq_headers(backend_fd, buf, n, pq_info, timeout_ms);
                if (sent < 0) { result.error = -1; goto done; }
            } else {
                /* Forward to backend */
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t w = send(backend_fd, buf + sent, (size_t)(n - sent), MSG_NOSIGNAL);
                    if (__builtin_expect(w < 0, 0)) {
                        if (errno == EINTR) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            /* Wait for backend to become writable */
                            struct pollfd wfd = { .fd = backend_fd, .events = POLLOUT };
                            poll(&wfd, 1, timeout_ms);
                            continue;
                        }
                        result.error = -1;
                        goto done;
                    }
                    sent += w;
                }
            }
        }

        /* Backend -> Client */
        if (fds[1].revents & POLLIN) {
            ssize_t n = recv(backend_fd, buf, sizeof(buf), 0);
            if (__builtin_expect(n <= 0, 0)) {
                /* Backend closed or error */
                break;
            }
            result.bytes_from_backend += (size_t)n;

            /* Forward to client via TLS */
            int written = 0;
            while (written < (int)n) {
                int w = SSL_write(ssl, buf + written, (int)(n - (ssize_t)written));
                if (__builtin_expect(w <= 0, 0)) {
                    int err = SSL_get_error(ssl, w);
                    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                        continue;
                    result.error = -1;
                    goto done;
                }
                written += w;
            }
        }

        /* Check for hangup/error on either side */
        if (__builtin_expect((fds[0].revents & (POLLHUP | POLLERR)) ||
                             (fds[1].revents & (POLLHUP | POLLERR)), 0)) {
            break;
        }
    }

done:
    return result;
}
