/**
 * @file sig_providers.h
 * @brief Signature Provider Implementations for Crypto-Agility Registry
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Wraps ML-DSA (FIPS 204) and classical signature algorithms into the
 * pluggable pq_sig_provider_t interface.
 */

#ifndef PQ_SIG_PROVIDERS_H
#define PQ_SIG_PROVIDERS_H

#include "crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ML-DSA (Post-Quantum) */
const pq_sig_provider_t *pq_sig_provider_mldsa44(void);
const pq_sig_provider_t *pq_sig_provider_mldsa65(void);
const pq_sig_provider_t *pq_sig_provider_mldsa87(void);

/* Classical Fallbacks */
const pq_sig_provider_t *pq_sig_provider_ed25519(void);

#ifdef __cplusplus
}
#endif

#endif /* PQ_SIG_PROVIDERS_H */
