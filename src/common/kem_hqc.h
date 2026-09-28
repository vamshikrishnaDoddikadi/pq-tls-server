/**
 * @file kem_hqc.h
 * @brief HQC (Hamming Quasi-Cyclic) KEM Provider
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * HQC is a code-based (non-lattice) KEM selected as a NIST round 4
 * candidate.  This provider validates the crypto-agility pluggable
 * architecture by demonstrating a non-lattice algorithm can be added
 * without changing core code.
 *
 * Sizes are NOT compile-time constants: metadata() reports the sizes of the
 * linked liboqs (HQC was renamed/resized across liboqs releases), and all
 * sizes are 0 and is_available() is false when liboqs was built without
 * HQC.  Always check is_available() and allocate from metadata().
 *
 * Can be compiled as either:
 *   - Built-in: linked directly into the server
 *   - Plugin: compiled as a .so and loaded at runtime via the registry
 */

#ifndef PQ_KEM_HQC_H
#define PQ_KEM_HQC_H

#include "crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/** HQC-128 provider (NIST Level 1, code-based) */
const pq_kem_provider_t *pq_kem_provider_hqc128(void);

/** HQC-192 provider (NIST Level 3, code-based) */
const pq_kem_provider_t *pq_kem_provider_hqc192(void);

/** HQC-256 provider (NIST Level 5, code-based) */
const pq_kem_provider_t *pq_kem_provider_hqc256(void);

#ifdef __cplusplus
}
#endif

#endif /* PQ_KEM_HQC_H */
