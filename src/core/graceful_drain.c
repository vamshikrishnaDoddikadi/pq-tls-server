/*
 * Graceful Connection Draining Implementation
 */

#include "graceful_drain.h"
#include "../http/h2_frame.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>

#define MAX_DRAINING_CONNECTIONS 1024

typedef struct {
    pq_draining_conn_t conn;
    int active;
} drain_pool_entry_t;

struct pq_drain_manager {
    drain_pool_entry_t pool[MAX_DRAINING_CONNECTIONS];
    int pool_count;
    int drain_timeout_sec;
    pthread_mutex_t lock;
};

/*
 * Create a new drain manager
 */
pq_drain_manager_t* pq_drain_manager_create(int drain_timeout_sec)
{
    pq_drain_manager_t *dm = malloc(sizeof(pq_drain_manager_t));
    if (!dm)
        return NULL;

    memset(dm, 0, sizeof(pq_drain_manager_t));
    dm->drain_timeout_sec = drain_timeout_sec > 0 ? drain_timeout_sec : 30;

    if (pthread_mutex_init(&dm->lock, NULL) != 0) {
        free(dm);
        return NULL;
    }

    return dm;
}

/*
 * Destroy drain manager and force-close all connections
 */
void pq_drain_manager_destroy(pq_drain_manager_t *dm)
{
    if (!dm)
        return;

    pthread_mutex_lock(&dm->lock);

    for (int i = 0; i < dm->pool_count; i++) {
        if (dm->pool[i].active) {
            pq_draining_conn_t *conn = &dm->pool[i].conn;
            if (conn->ssl)
                SSL_free(conn->ssl);
            if (conn->fd >= 0)
                close(conn->fd);
        }
    }

    pthread_mutex_unlock(&dm->lock);
    pthread_mutex_destroy(&dm->lock);
    free(dm);
}

/*
 * Send GOAWAY frame for HTTP/2 connection
 * Returns: 0 on success, -1 on error
 *
 * Ensures proper last-stream-id is set to prevent clients from creating
 * new streams after receiving GOAWAY. Uses only streams that have been
 * explicitly created by the client.
 */
static int send_goaway(int fd, SSL *ssl, uint32_t last_stream)
{
    uint8_t buf[H2_FRAME_HEADER_SIZE + 8];

    /* Validate last_stream_id: must be even (client-initiated streams)
       or 0 if no streams processed. Odd stream IDs are server-initiated. */
    if (last_stream > 0 && (last_stream & 1) != 0) {
        /* Server-initiated stream ID in GOAWAY is invalid. Use 0 instead. */
        last_stream = 0;
    }

    int bytes = h2_frame_encode_goaway(buf, sizeof(buf), last_stream, H2_NO_ERROR);
    if (bytes < 0)
        return -1;

    /* Try to send via SSL if available, otherwise raw socket */
    if (ssl) {
        int written = SSL_write(ssl, buf, bytes);
        if (written <= 0)
            return -1;
    } else {
        ssize_t written = send(fd, buf, bytes, MSG_NOSIGNAL);
        if (written < bytes)
            return -1;
    }

    return 0;
}

/*
 * Add a connection to the draining pool
 */
int pq_drain_add(pq_drain_manager_t *dm, pq_draining_conn_t *conn)
{
    if (!dm || !conn || conn->fd < 0)
        return -1;

    pthread_mutex_lock(&dm->lock);

    if (dm->pool_count >= MAX_DRAINING_CONNECTIONS) {
        pthread_mutex_unlock(&dm->lock);
        return -1;
    }

    int idx = dm->pool_count;
    memcpy(&dm->pool[idx].conn, conn, sizeof(pq_draining_conn_t));
    dm->pool[idx].conn.drain_start = time(NULL);
    dm->pool[idx].active = 1;
    dm->pool_count++;

    pthread_mutex_unlock(&dm->lock);

    /* Send GOAWAY for HTTP/2 connections */
    if (conn->h2) {
        send_goaway(conn->fd, conn->ssl, conn->last_stream);
    }

    return 0;
}

/*
 * Process draining connections
 * Returns: number of connections still draining
 */
int pq_drain_tick(pq_drain_manager_t *dm)
{
    if (!dm)
        return 0;

    pthread_mutex_lock(&dm->lock);

    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);
    time_t now = now_ts.tv_sec;
    int still_draining = 0;

    for (int i = 0; i < dm->pool_count; i++) {
        if (!dm->pool[i].active)
            continue;

        pq_draining_conn_t *conn = &dm->pool[i].conn;
        int elapsed = (int)(now - conn->drain_start);

        if (elapsed >= dm->drain_timeout_sec) {
            /* Force-close expired connection */
            if (conn->ssl)
                SSL_free(conn->ssl);
            if (conn->fd >= 0)
                close(conn->fd);
            dm->pool[i].active = 0;
        } else {
            /* Try graceful SSL shutdown */
            if (conn->ssl) {
                int ret = SSL_shutdown(conn->ssl);
                if (ret < 0) {
                    /* Error or would block - leave connection open for now */
                    still_draining++;
                } else if (ret == 0) {
                    /* Need to retry SSL_shutdown */
                    still_draining++;
                } else {
                    /* SSL shutdown complete — free SSL handle before closing fd */
                    SSL_free(conn->ssl);
                    conn->ssl = NULL;
                    if (conn->fd >= 0)
                        close(conn->fd);
                    dm->pool[i].active = 0;
                }
            } else {
                /* No SSL, just wait for timeout then close */
                still_draining++;
            }
        }
    }

    /* Compact the array by removing inactive entries */
    int write_idx = 0;
    for (int i = 0; i < dm->pool_count; i++) {
        if (dm->pool[i].active) {
            if (write_idx != i) {
                memcpy(&dm->pool[write_idx], &dm->pool[i], sizeof(drain_pool_entry_t));
            }
            write_idx++;
        }
    }
    dm->pool_count = write_idx;

    pthread_mutex_unlock(&dm->lock);

    return still_draining;
}

/*
 * Force-close all draining connections immediately
 */
void pq_drain_shutdown_all(pq_drain_manager_t *dm)
{
    if (!dm)
        return;

    pthread_mutex_lock(&dm->lock);

    for (int i = 0; i < dm->pool_count; i++) {
        if (dm->pool[i].active) {
            pq_draining_conn_t *conn = &dm->pool[i].conn;
            if (conn->ssl)
                SSL_free(conn->ssl);
            if (conn->fd >= 0)
                close(conn->fd);
            dm->pool[i].active = 0;
        }
    }

    dm->pool_count = 0;

    pthread_mutex_unlock(&dm->lock);
}
