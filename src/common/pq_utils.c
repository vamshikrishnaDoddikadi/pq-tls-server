/**
 * @file pq_utils.c
 * @brief Post-Quantum TLS Utilities Implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 */

#include "pq_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

/* Global logging state */
static struct {
    FILE *log_file;
    log_level_t level;
    int initialized;
} log_state = {NULL, LOG_INFO, 0};

/* Logging functions */
void pq_log_init(const char *log_file, log_level_t level) {
    if (log_state.initialized) {
        return;
    }

    if (log_file) {
        log_state.log_file = fopen(log_file, "w");
        if (!log_state.log_file) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
            return;
        }
    } else {
        log_state.log_file = stderr;
    }

    log_state.level = level;
    log_state.initialized = 1;
}

void pq_log(log_level_t level, const char *format, ...) {
    if (!log_state.initialized || level < log_state.level) {
        return;
    }

    FILE *out = log_state.log_file ? log_state.log_file : stderr;

    static const char *level_str[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
    static const int level_count = sizeof(level_str) / sizeof(level_str[0]);

    /* Bounds check to prevent out-of-range array access */
    const char *lstr = (level >= 0 && level < level_count) ? level_str[level] : "UNKNOWN";

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(out, "[%s] [%s] ", time_buf, lstr);

    va_list args;
    va_start(args, format);
    vfprintf(out, format, args);
    va_end(args);

    fprintf(out, "\n");
    fflush(out);
}

void pq_log_cleanup(void) {
    if (log_state.log_file && log_state.log_file != stderr) {
        fclose(log_state.log_file);
    }
    log_state.initialized = 0;
    log_state.log_file = NULL;
}

/* Timer functions */
pq_timer_t* pq_timer_create(void) {
    pq_timer_t *timer = malloc(sizeof(pq_timer_t));
    if (!timer) {
        return NULL;
    }
    memset(timer, 0, sizeof(pq_timer_t));
    return timer;
}

void pq_timer_start(pq_timer_t *timer) {
    if (timer) {
        clock_gettime(CLOCK_MONOTONIC, &timer->start_time);
    }
}

void pq_timer_stop(pq_timer_t *timer) {
    if (timer) {
        clock_gettime(CLOCK_MONOTONIC, &timer->end_time);
        timer->elapsed_ms = (timer->end_time.tv_sec - timer->start_time.tv_sec) * 1000.0 +
                           (timer->end_time.tv_nsec - timer->start_time.tv_nsec) / 1000000.0;
    }
}

double pq_timer_elapsed(pq_timer_t *timer) {
    if (timer) {
        return timer->elapsed_ms;
    }
    return 0.0;
}

void pq_timer_destroy(pq_timer_t *timer) {
    free(timer);
}

/* Memory functions */
void* pq_malloc(size_t size) {
    return malloc(size);
}

void* pq_calloc(size_t count, size_t size) {
    return calloc(count, size);
}

void* pq_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

void pq_free(void *ptr) {
    free(ptr);
}

void pq_secure_memzero(void *ptr, size_t size) {
    volatile unsigned char *v = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < size; i++) {
        v[i] = 0;
    }
}

/* String utilities */
char* pq_strdup(const char *str) {
    if (!str) {
        return NULL;
    }
    size_t len = strlen(str);
    char *dup = malloc(len + 1);
    if (dup) {
        memcpy(dup, str, len + 1);
    }
    return dup;
}

size_t pq_strlcpy(char *dst, const char *src, size_t size) {
    if (!dst || !src || size == 0) {
        return 0;
    }
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < size - 1) ? src_len : size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return src_len;
}

size_t pq_strlcat(char *dst, const char *src, size_t size) {
    if (!dst || !src || size == 0) {
        return 0;
    }
    size_t dst_len = strlen(dst);
    size_t src_len = strlen(src);

    /* If dst already fills or overflows the buffer, no room to append */
    if (dst_len >= size - 1) {
        return dst_len + src_len;
    }

    size_t space = size - dst_len - 1;
    size_t copy_len = (src_len < space) ? src_len : space;
    memcpy(dst + dst_len, src, copy_len);
    dst[dst_len + copy_len] = '\0';
    return dst_len + src_len;
}

/* Error handling */
pq_error_t* pq_error_create(int code, const char *message) {
    pq_error_t *error = malloc(sizeof(pq_error_t));
    if (error) {
        error->code = code;
        if (message) {
            pq_strlcpy(error->message, message, sizeof(error->message));
        } else {
            error->message[0] = '\0';
        }
    }
    return error;
}

void pq_error_set(pq_error_t *error, int code, const char *format, ...) {
    if (!error) {
        return;
    }
    error->code = code;
    va_list args;
    va_start(args, format);
    vsnprintf(error->message, sizeof(error->message), format, args);
    va_end(args);
}

void pq_error_destroy(pq_error_t *error) {
    free(error);
}

const char* pq_error_message(pq_error_t *error) {
    if (error) {
        return error->message;
    }
    return "Unknown error";
}

/* Byte utilities */
void pq_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_str) {
    if (!bytes || !hex_str) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + i * 2, "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

int pq_hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t max_len) {
    if (!hex_str || !bytes) {
        return -1;
    }
    size_t len = strlen(hex_str) / 2;
    if (len > max_len) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        char byte_str[3] = {hex_str[i * 2], hex_str[i * 2 + 1], '\0'};
        bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return len;
}
