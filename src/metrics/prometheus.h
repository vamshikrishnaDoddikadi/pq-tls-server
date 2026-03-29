/**
 * @file prometheus.h
 * @brief Prometheus-compatible metrics export
 * @author Vamshi Krishna Doddikadi
 */

#ifndef PQ_PROMETHEUS_H
#define PQ_PROMETHEUS_H

#include "../core/connection_manager.h"
#include <stddef.h>

/**
 * Format all server metrics in Prometheus exposition format.
 * Writes to buf, returns number of bytes written.
 */
int pq_prometheus_format(const pq_conn_manager_t *mgr, char *buf, size_t len);

#endif /* PQ_PROMETHEUS_H */
