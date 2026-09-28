/**
 * @file kem_classical.h
 * @brief Classical KEM Providers (X25519, ECDH P-256) for Crypto-Agility Registry
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Wraps classical key exchange algorithms into the pq_kem_provider_t interface.
 * These are used as the classical component in hybrid KEM pairs and as
 * standalone fallbacks.
 *
 * Also exports small raw-key P-256 helpers (OpenSSL 3 EVP/OSSL_PARAM based,
 * no deprecated EC_KEY APIs) shared by hybrid_kex.c and pq_sig.c.
 */

#ifndef PQ_KEM_CLASSICAL_H
#define PQ_KEM_CLASSICAL_H

#include "crypto_provider.h"
#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** X25519 ECDH provider (128-bit classical security) */
const pq_kem_provider_t *pq_kem_provider_x25519(void);

/** ECDH P-256 provider (128-bit classical security) */
const pq_kem_provider_t *pq_kem_provider_p256(void);

/* ========================================================================
 * Raw P-256 key helpers
 *
 * Raw formats: public key = uncompressed SEC1 point (0x04 || X || Y, 65 bytes),
 * private key = 32-byte big-endian scalar d with 1 <= d < n.
 * ======================================================================== */

#define PQ_P256_PUBLICKEY_BYTES    65
#define PQ_P256_SECRETKEY_BYTES    32
#define PQ_P256_SHAREDSECRET_BYTES 32

/** Generate a P-256 key pair in raw form.  @p sk is wiped on failure. */
int pq_p256_generate_raw(uint8_t pk[PQ_P256_PUBLICKEY_BYTES],
                         uint8_t sk[PQ_P256_SECRETKEY_BYTES]);

/** Compute the raw public key d*G for a raw private key (range-checked). */
int pq_p256_public_from_private(const uint8_t sk[PQ_P256_SECRETKEY_BYTES],
                                uint8_t pk[PQ_P256_PUBLICKEY_BYTES]);

/**
 * Build an EVP_PKEY key pair from a raw private key (the public point is
 * recomputed).  Caller frees *out with EVP_PKEY_free().
 */
int pq_p256_pkey_from_private(const uint8_t sk[PQ_P256_SECRETKEY_BYTES], EVP_PKEY **out);

/**
 * Build an EVP_PKEY public key from a raw uncompressed point.  The point is
 * validated (correct encoding, on the curve, not the identity).
 */
int pq_p256_pkey_from_public(const uint8_t pk[PQ_P256_PUBLICKEY_BYTES], EVP_PKEY **out);

/** Raw ECDH: ss = x-coordinate of d * peer_pk (peer point validated). */
int pq_p256_ecdh_raw(const uint8_t sk[PQ_P256_SECRETKEY_BYTES],
                     const uint8_t peer_pk[PQ_P256_PUBLICKEY_BYTES],
                     uint8_t ss[PQ_P256_SHAREDSECRET_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQ_KEM_CLASSICAL_H */
