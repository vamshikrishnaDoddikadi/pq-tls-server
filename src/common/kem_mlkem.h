/**
 * @file kem_mlkem.h
 * @brief ML-KEM Provider Implementations for Crypto-Agility Registry
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Wraps the existing liboqs ML-KEM-512/768/1024 (FIPS 203) into the
 * pluggable pq_kem_provider_t interface.
 */

#ifndef PQ_KEM_MLKEM_H
#define PQ_KEM_MLKEM_H

#include "crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/** ML-KEM-512 provider (NIST Level 1, 128-bit quantum security) */
const pq_kem_provider_t *pq_kem_provider_mlkem512(void);

/** ML-KEM-768 provider (NIST Level 3, 192-bit quantum security) */
const pq_kem_provider_t *pq_kem_provider_mlkem768(void);

/** ML-KEM-1024 provider (NIST Level 5, 256-bit quantum security) */
const pq_kem_provider_t *pq_kem_provider_mlkem1024(void);

#ifdef __cplusplus
}
#endif

#endif /* PQ_KEM_MLKEM_H */
