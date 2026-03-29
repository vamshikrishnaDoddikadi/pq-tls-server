/**
 * @file log_streamer.c
 * @brief Ring buffer log collector + SSE streaming to management clients
 */

#include "log_streamer.h"

#include "json_helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct {
    char     level[8];
    char     message[LOG_LINE_MAX];
    char     timestamp[32];
} log_entry_t;

static struct {
    log_entry_t     ring[LOG_RING_SIZE];
    int             head;       /* Next write position */
    int             count;      /* Total entries in ring */
    pthread_mutex_t mutex;
    atomic_int      initialized;
    atomic_int      running;
} ls;

void log_streamer_init(const char *log_file) {
    (void)log_file; /* File tailing not used — we capture via push */
    memset(&ls, 0, sizeof(ls));
    pthread_mutex_init(&ls.mutex, NULL);
    atomic_store(&ls.initialized, 1);
    atomic_store(&ls.running, 1);
}

void log_streamer_push(const char *level, const char *message) {
    if (!atomic_load(&ls.initialized) || !level || !message) return;

    pthread_mutex_lock(&ls.mutex);

    log_entry_t *e = &ls.ring[ls.head];
    strncpy(e->level, level, sizeof(e->level) - 1);
    e->level[sizeof(e->level) - 1] = '\0';
    strncpy(e->message, message, sizeof(e->message) - 1);
    e->message[sizeof(e->message) - 1] = '\0';

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(e->timestamp, sizeof(e->timestamp), "%Y-%m-%d %H:%M:%S", &tm);

    ls.head = (ls.head + 1) % LOG_RING_SIZE;
    if (ls.count < LOG_RING_SIZE) ls.count++;

    pthread_mutex_unlock(&ls.mutex);
}

int log_streamer_recent(char *buf, size_t cap, int count) {
    if (!buf || cap == 0) return 0;
    if (!atomic_load(&ls.initialized)) {
        snprintf(buf, cap, "[]");
        return 2;
    }

    pthread_mutex_lock(&ls.mutex);

    int total = ls.count;
    if (count <= 0 || count > total) count = total;

    int start_idx = (ls.head - count + LOG_RING_SIZE) % LOG_RING_SIZE;

    json_builder_t jb;
    jb_init(&jb, buf, cap);
    jb_array_start(&jb);

    for (int i = 0; i < count; i++) {
        int idx = (start_idx + i) % LOG_RING_SIZE;
        log_entry_t *e = &ls.ring[idx];

        jb_object_start(&jb);
        jb_key_str(&jb, "ts", e->timestamp);
        jb_key_str(&jb, "level", e->level);
        jb_key_str(&jb, "msg", e->message);
        jb_object_end(&jb);
        if (jb.error) break;
    }

    jb_array_end(&jb);
    size_t pos = jb_finish(&jb);
    if (pos == 0) {
        snprintf(buf, cap, "[]");
        pos = 2;
    }

    pthread_mutex_unlock(&ls.mutex);
    return (int)pos;
}

void log_streamer_stream_sse(int client_fd) {
    if (!atomic_load(&ls.initialized)) return;

    /* Send SSE headers */
    const char *headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: keep-alive\r\n\r\n";
    send(client_fd, headers, strlen(headers), MSG_NOSIGNAL);

    int last_head = ls.head;

    while (atomic_load(&ls.running)) {
        pthread_mutex_lock(&ls.mutex);

        int current_head = ls.head;
        if (current_head != last_head) {
            /* Send new entries */
            int start = last_head;
            int end = current_head;

            while (start != end) {
                log_entry_t *e = &ls.ring[start];

                /* Build properly escaped JSON */
                char json_buf[LOG_LINE_MAX + 256];
                json_builder_t jb;
                jb_init(&jb, json_buf, sizeof(json_buf));
                jb_object_start(&jb);
                jb_key_str(&jb, "ts", e->timestamp);
                jb_key_str(&jb, "level", e->level);
                jb_key_str(&jb, "msg", e->message);
                jb_object_end(&jb);
                jb_finish(&jb);

                char event[LOG_LINE_MAX + 300];
                int n = snprintf(event, sizeof(event), "data: %s\n\n", json_buf);

                if (n > 0) {
                    ssize_t sent = send(client_fd, event, (size_t)n, MSG_NOSIGNAL);
                    if (sent <= 0) {
                        pthread_mutex_unlock(&ls.mutex);
                        goto done;
                    }
                }

                start = (start + 1) % LOG_RING_SIZE;
            }
            last_head = current_head;
        }

        pthread_mutex_unlock(&ls.mutex);
        usleep(500000); /* 500ms poll interval */
    }

done:
    close(client_fd);
}

void log_streamer_cleanup(void) {
    if (!atomic_load(&ls.initialized)) return;
    atomic_store(&ls.running, 0);
    atomic_store(&ls.initialized, 0);
    /* Give SSE streams time to notice running=0 and exit */
    usleep(600000);
    pthread_mutex_destroy(&ls.mutex);
}
