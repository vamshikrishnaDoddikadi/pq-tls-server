/*
 * conn_pool.c - Backend Connection Pool Implementation
 */

#include "conn_pool.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>

#define PQ_MAX_UPSTREAMS 16

/* Connection pool list node */
typedef struct conn_node {
    pq_pooled_conn_t conn;
    struct conn_node *next;
} conn_node_t;

/* Connection pool structure */
struct pq_conn_pool {
    conn_node_t    *lists[PQ_MAX_UPSTREAMS];  /* One list per upstream */
    int             max_per_backend;
    int             max_total;
    int             current_total;
    pthread_mutex_t lock;
};

pq_conn_pool_t* pq_conn_pool_create(int max_per_backend, int max_total)
{
    if (max_per_backend <= 0 || max_total <= 0)
        return NULL;

    pq_conn_pool_t *pool = malloc(sizeof(*pool));
    if (!pool)
        return NULL;

    memset(pool, 0, sizeof(*pool));
    pool->max_per_backend = max_per_backend;
    pool->max_total = max_total;

    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool);
        return NULL;
    }

    return pool;
}

void pq_conn_pool_destroy(pq_conn_pool_t *pool)
{
    if (!pool)
        return;

    pthread_mutex_lock(&pool->lock);

    for (int i = 0; i < PQ_MAX_UPSTREAMS; i++) {
        conn_node_t *node = pool->lists[i];
        while (node) {
            conn_node_t *next = node->next;
            if (node->conn.fd >= 0)
                close(node->conn.fd);
            free(node);
            node = next;
        }
    }

    pthread_mutex_unlock(&pool->lock);
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

/* Check if a connection is still alive using MSG_PEEK */
static int is_connection_alive(int fd)
{
    char byte;
    int result = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    /* result == 0 means EOF (connection closed) */
    if (result == 0)
        return 0;
    /* result > 0 means data available (good) */
    if (result > 0)
        return 1;
    /* result == -1: EAGAIN/EWOULDBLOCK means no data yet (connection alive),
       any other errno means the connection is broken */
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 1;
    return 0;
}

__attribute__((hot))
pq_pooled_conn_t* pq_conn_pool_acquire(pq_conn_pool_t *pool, int upstream_idx)
{
    if (__builtin_expect(!pool || upstream_idx < 0 || upstream_idx >= PQ_MAX_UPSTREAMS, 0))
        return NULL;

    pthread_mutex_lock(&pool->lock);

    conn_node_t *node = pool->lists[upstream_idx];
    conn_node_t *prev = NULL;

    while (node) {
        /* Check if connection is still alive */
        if (__builtin_expect(is_connection_alive(node->conn.fd), 1)) {
            /* Found a good connection */
            node->conn.in_use = 1;
            node->conn.last_used = time(NULL);

            /* Remove from list */
            if (prev)
                prev->next = node->next;
            else
                pool->lists[upstream_idx] = node->next;

            /* Copy connection before freeing node to avoid use-after-free */
            pq_pooled_conn_t *result = malloc(sizeof(*result));
            if (__builtin_expect(result != NULL, 1)) {
                memcpy(result, &node->conn, sizeof(*result));
                free(node);
                pthread_mutex_unlock(&pool->lock);
                return result;
            }
            /* Allocation failed, put node back */
            node->next = pool->lists[upstream_idx];
            pool->lists[upstream_idx] = node;
            pthread_mutex_unlock(&pool->lock);
            return NULL;
        }

        /* Connection is dead, remove it */
        if (prev)
            prev->next = node->next;
        else
            pool->lists[upstream_idx] = node->next;

        if (node->conn.fd >= 0)
            close(node->conn.fd);

        conn_node_t *dead_node = node;
        node = node->next;
        pool->current_total--;
        free(dead_node);
    }

    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

void pq_conn_pool_release(pq_conn_pool_t *pool, pq_pooled_conn_t *conn)
{
    if (!pool || !conn || conn->upstream_idx < 0 || conn->upstream_idx >= PQ_MAX_UPSTREAMS)
        return;

    conn->in_use = 0;
    conn->last_used = time(NULL);

    /* Fast-path: count existing connections for this upstream */
    int count = 0;
    pthread_mutex_lock(&pool->lock);
    {
        conn_node_t *node = pool->lists[conn->upstream_idx];
        while (node) {
            count++;
            node = node->next;
        }
    }
    /* Minimize critical section: only protect list operations */
    if (__builtin_expect(count < pool->max_per_backend && pool->current_total < pool->max_total, 1)) {
        conn_node_t *new_node = malloc(sizeof(*new_node));
        if (__builtin_expect(new_node != NULL, 1)) {
            memcpy(&new_node->conn, conn, sizeof(*conn));
            new_node->next = pool->lists[conn->upstream_idx];
            pool->lists[conn->upstream_idx] = new_node;
            pool->current_total++;
            pthread_mutex_unlock(&pool->lock);
            free(conn);
            return;
        }
    }
    pthread_mutex_unlock(&pool->lock);

    /* Can't return to pool, close it */
    if (conn->fd >= 0)
        close(conn->fd);
    free(conn);
}

void pq_conn_pool_remove(pq_conn_pool_t *pool, pq_pooled_conn_t *conn)
{
    if (!pool || !conn || conn->upstream_idx < 0 || conn->upstream_idx >= PQ_MAX_UPSTREAMS)
        return;

    pthread_mutex_lock(&pool->lock);

    if (conn->fd >= 0)
        close(conn->fd);
    pool->current_total--;

    pthread_mutex_unlock(&pool->lock);
    free(conn);
}

void pq_conn_pool_cleanup(pq_conn_pool_t *pool, int max_idle_sec)
{
    if (!pool || max_idle_sec <= 0)
        return;

    pthread_mutex_lock(&pool->lock);

    time_t now = time(NULL);

    for (int i = 0; i < PQ_MAX_UPSTREAMS; i++) {
        conn_node_t *node = pool->lists[i];
        conn_node_t *prev = NULL;

        while (node) {
            time_t idle_time = now - node->conn.last_used;

            if (idle_time > max_idle_sec && !node->conn.in_use) {
                /* Remove this connection */
                if (prev)
                    prev->next = node->next;
                else
                    pool->lists[i] = node->next;

                if (node->conn.fd >= 0)
                    close(node->conn.fd);

                conn_node_t *dead_node = node;
                node = node->next;
                pool->current_total--;
                free(dead_node);
            } else {
                prev = node;
                node = node->next;
            }
        }
    }

    pthread_mutex_unlock(&pool->lock);
}

int pq_conn_pool_stats(const pq_conn_pool_t *pool, int *active, int *idle)
{
    if (!pool)
        return -1;

    pthread_mutex_lock((pthread_mutex_t *)&pool->lock);

    int idle_count = 0;
    int active_count = 0;

    for (int i = 0; i < PQ_MAX_UPSTREAMS; i++) {
        conn_node_t *node = pool->lists[i];
        while (node) {
            if (node->conn.in_use)
                active_count++;
            else
                idle_count++;
            node = node->next;
        }
    }

    if (active)
        *active = active_count;
    if (idle)
        *idle = idle_count;

    pthread_mutex_unlock((pthread_mutex_t *)&pool->lock);

    return active_count + idle_count;
}
