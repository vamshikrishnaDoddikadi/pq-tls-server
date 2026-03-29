/**
 * @file pq_utils.h
 * @brief Post-Quantum TLS Utilities Header
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 */

#ifndef PQ_UTILS_H
#define PQ_UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* Logging levels */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
} log_level_t;

/* Logging functions */
void pq_log_init(const char *log_file, log_level_t level);
void pq_log(log_level_t level, const char *format, ...);
void pq_log_cleanup(void);

/* Performance metrics */
typedef struct {
    struct timespec start_time;
    struct timespec end_time;
    double elapsed_ms;
} pq_timer_t;

pq_timer_t* pq_timer_create(void);
void pq_timer_start(pq_timer_t *timer);
void pq_timer_stop(pq_timer_t *timer);
double pq_timer_elapsed(pq_timer_t *timer);
void pq_timer_destroy(pq_timer_t *timer);

/* Memory utilities */
void* pq_malloc(size_t size);
void* pq_calloc(size_t count, size_t size);
void* pq_realloc(void *ptr, size_t size);
void pq_free(void *ptr);

/* Secure memory clearing */
void pq_secure_memzero(void *ptr, size_t size);

/* String utilities */
char* pq_strdup(const char *str);
size_t pq_strlcpy(char *dst, const char *src, size_t size);
size_t pq_strlcat(char *dst, const char *src, size_t size);

/* Error handling */
typedef struct {
    int code;
    char message[256];
} pq_error_t;

pq_error_t* pq_error_create(int code, const char *message);
void pq_error_set(pq_error_t *error, int code, const char *format, ...);
void pq_error_destroy(pq_error_t *error);
const char* pq_error_message(pq_error_t *error);

/* Byte utilities */
void pq_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_str);
int pq_hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t max_len);

#endif /* PQ_UTILS_H */
