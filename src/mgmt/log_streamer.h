/**
 * @file log_streamer.h
 * @brief Log file tailing and SSE streaming
 */

#ifndef PQ_LOG_STREAMER_H
#define PQ_LOG_STREAMER_H

#include <stddef.h>

#define LOG_STREAM_MAX_CLIENTS 8
#define LOG_RING_SIZE          512
#define LOG_LINE_MAX           1024

/**
 * Initialize the log streamer. Call once at startup.
 * @param log_file Path to the server log file (NULL for no file tailing).
 */
void log_streamer_init(const char *log_file);

/**
 * Push a log line into the ring buffer (called from LOG macros).
 * Thread-safe.
 */
void log_streamer_push(const char *level, const char *message);

/**
 * Get recent log lines as JSON array.
 * @param buf    Output buffer
 * @param cap    Buffer capacity
 * @param count  Max number of lines to return
 * @return Number of bytes written.
 */
int log_streamer_recent(char *buf, size_t cap, int count);

/**
 * Stream log lines to a client fd via SSE.
 * Blocks until client disconnects or server stops.
 * Should be called from a dedicated thread.
 */
void log_streamer_stream_sse(int client_fd);

/**
 * Clean up log streamer resources.
 */
void log_streamer_cleanup(void);

#endif /* PQ_LOG_STREAMER_H */
