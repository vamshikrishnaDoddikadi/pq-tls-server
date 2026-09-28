/**
 * @file prometheus.c
 * @brief Prometheus-compatible metrics export
 * @author Vamshi Krishna Doddikadi
 */

#include "prometheus.h"
#include <stdio.h>
#include <stdatomic.h>
#include <time.h>
#include <openssl/crypto.h>
#include <oqs/oqs.h>

#ifndef PQ_TLS_SERVER_VERSION
#define PQ_TLS_SERVER_VERSION "unknown"
#endif

int pq_prometheus_format(const pq_conn_manager_t *mgr, char *buf, size_t len) {
    return snprintf(buf, len,
        "# HELP pqtls_connections_total Total connections accepted\n"
        "# TYPE pqtls_connections_total counter\n"
        "pqtls_connections_total %ld\n"
        "\n"
        "# HELP pqtls_connections_active Currently active connections\n"
        "# TYPE pqtls_connections_active gauge\n"
        "pqtls_connections_active %d\n"
        "\n"
        "# HELP pqtls_handshake_failures_total TLS handshake failures\n"
        "# TYPE pqtls_handshake_failures_total counter\n"
        "pqtls_handshake_failures_total %ld\n"
        "\n"
        "# HELP pqtls_bytes_received_total Bytes received from clients\n"
        "# TYPE pqtls_bytes_received_total counter\n"
        "pqtls_bytes_received_total %ld\n"
        "\n"
        "# HELP pqtls_bytes_sent_total Bytes sent to clients\n"
        "# TYPE pqtls_bytes_sent_total counter\n"
        "pqtls_bytes_sent_total %ld\n"
        "\n"
        "# HELP pqtls_pq_negotiations_total Post-quantum key exchanges negotiated\n"
        "# TYPE pqtls_pq_negotiations_total counter\n"
        "pqtls_pq_negotiations_total %ld\n"
        "\n"
        "# HELP pqtls_classical_negotiations_total Classical key exchanges negotiated\n"
        "# TYPE pqtls_classical_negotiations_total counter\n"
        "pqtls_classical_negotiations_total %ld\n"
        "\n"
        "# HELP pqtls_pq_rejected_total Connections refused because they could not negotiate PQ (--require-pq)\n"
        "# TYPE pqtls_pq_rejected_total counter\n"
        "pqtls_pq_rejected_total %ld\n"
        "\n"
        "# HELP pqtls_rate_limited_total Connections refused by the per-IP rate limiter\n"
        "# TYPE pqtls_rate_limited_total counter\n"
        "pqtls_rate_limited_total %ld\n"
        "\n"
        "# HELP pqtls_overload_rejected_total Connections refused because max_connections was reached\n"
        "# TYPE pqtls_overload_rejected_total counter\n"
        "pqtls_overload_rejected_total %ld\n"
        "\n"
        "# HELP pqtls_bad_requests_total Requests rejected by the proxy (400/408/431)\n"
        "# TYPE pqtls_bad_requests_total counter\n"
        "pqtls_bad_requests_total %ld\n"
        "\n"
        "# HELP pqtls_pq_available 1 if a post-quantum key exchange group is offered\n"
        "# TYPE pqtls_pq_available gauge\n"
        "pqtls_pq_available %d\n"
        "\n"
        "# HELP pqtls_pq_required 1 if clients must negotiate post-quantum key exchange\n"
        "# TYPE pqtls_pq_required gauge\n"
        "pqtls_pq_required %d\n"
        "\n"
        "# HELP pqtls_max_connections Configured connection limit\n"
        "# TYPE pqtls_max_connections gauge\n"
        "pqtls_max_connections %d\n"
        "\n"
        "# HELP pqtls_workers Number of acceptor threads\n"
        "# TYPE pqtls_workers gauge\n"
        "pqtls_workers %d\n"
        "\n"
        "# HELP pqtls_uptime_seconds Seconds since the server started\n"
        "# TYPE pqtls_uptime_seconds gauge\n"
        "pqtls_uptime_seconds %ld\n"
        "\n"
        "# HELP pqtls_build_info Build information\n"
        "# TYPE pqtls_build_info gauge\n"
        "pqtls_build_info{version=\"%s\",openssl=\"%s\",liboqs=\"%s\"} 1\n",
        atomic_load(&mgr->total_connections),
        atomic_load(&mgr->active_connections),
        atomic_load(&mgr->total_handshake_failures),
        atomic_load(&mgr->total_bytes_in),
        atomic_load(&mgr->total_bytes_out),
        atomic_load(&mgr->pq_negotiations),
        atomic_load(&mgr->classical_negotiations),
        atomic_load(&mgr->rejected_non_pq),
        atomic_load(&mgr->rate_limited_connections),
        atomic_load(&mgr->rejected_overload),
        atomic_load(&mgr->bad_requests),
        atomic_load(&mgr->pq_available) ? 1 : 0,
        mgr->config->require_pq ? 1 : 0,
        mgr->slot_count,
        mgr->worker_count,
        (long)(time(NULL) - mgr->start_time),
        PQ_TLS_SERVER_VERSION,
        OpenSSL_version(OPENSSL_VERSION_STRING),
        OQS_version());
}
