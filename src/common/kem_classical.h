/**
 * @file kem_classical.h
 * @brief Classical KEM Providers (X25519, ECDH P-256) for Crypto-Agility Registry
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Wraps classical key exchange algorithms into the pq_kem_provider_t interface.
 * These are used as the classical component in hybrid KEM pairs and as
 * standalone fallbacks.
 */

#ifndef PQ_KEM_CLASSICAL_H
#define PQ_KEM_CLASSICAL_H

#include "crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/** X25519 ECDH provider (128-bit classical security) */
const pq_kem_provider_t *pq_kem_provider_x25519(void);

/** ECDH P-256 provider (128-bit classical security) */
const pq_kem_provider_t *pq_kem_provider_p256(void);

#ifdef __cplusplus
}
#endif

#endif /* PQ_KEM_CLASSICAL_H */
