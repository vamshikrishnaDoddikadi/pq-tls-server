/**
 * @file hybrid_combiner.h
 * @brief Pluggable Hybrid Combiner Implementations
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Provides built-in hybrid combiners for merging classical and PQ
 * shared secrets.  The combiner is itself pluggable to accommodate
 * different standards bodies' requirements (IETF, NIST, etc.).
 *
 * Built-in combiners:
 *   - KDF-Concat: HKDF-SHA256(classical_ss || pq_ss) — IETF hybrid draft
 *   - XOR: classical_ss XOR pq_ss (fixed 32 bytes)
 */

#ifndef PQ_HYBRID_COMBINER_H
#define PQ_HYBRID_COMBINER_H

#include "crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the KDF-Concat combiner (IETF draft aligned)
 *
 * Combines shared secrets as: HKDF-SHA256(salt="", ikm=classical_ss||pq_ss,
 *   info=context, L=32)
 * Output is always 32 bytes.
 */
const pq_hybrid_combiner_t *pq_combiner_kdf_concat(void);

/**
 * @brief Get the XOR combiner
 *
 * Combines shared secrets as: classical_ss XOR pq_ss
 * Both inputs must be exactly 32 bytes; output is 32 bytes.
 */
const pq_hybrid_combiner_t *pq_combiner_xor(void);

#ifdef __cplusplus
}
#endif

#endif /* PQ_HYBRID_COMBINER_H */
