/**
 * @file bench.h
 * @brief PQ algorithm benchmarking suite
 * @author Vamshi Krishna Doddikadi
 *
 * Built-in benchmarking for comparing post-quantum vs classical algorithms:
 *   - ML-KEM-768 vs X25519 key exchange
 *   - ML-DSA-65 vs Ed25519 signatures
 *   - Full TLS 1.3 handshake timing (PQ vs classical)
 *
 * Output formats: human-readable table, JSON, CSV
 */

#ifndef PQ_BENCH_H
#define PQ_BENCH_H

typedef enum {
    PQ_BENCH_FORMAT_TABLE,
    PQ_BENCH_FORMAT_JSON,
    PQ_BENCH_FORMAT_CSV
} pq_bench_format_t;

/**
 * Run the full benchmark suite and print results.
 * @param iterations  Number of iterations per test
 * @param format      Output format
 * @return 0 on success
 */
int pq_bench_run(int iterations, pq_bench_format_t format);

#endif /* PQ_BENCH_H */
