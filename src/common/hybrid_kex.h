/**
 * @file hybrid_kex.h
 * @brief Hybrid Key Exchange combining classical and post-quantum algorithms
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements hybrid key exchange mechanisms that combine classical
 * ECDH algorithms (X25519, ECDH P-256) with post-quantum ML-KEM algorithms
 * to provide defense-in-depth security.
 *
 * Supported modes:
 * - CONCAT: Concatenate classical and PQ shared secrets
 * - XOR: XOR classical and PQ shared secrets (fixed 32-byte output)
 */

#ifndef HYBRID_KEX_H
#define HYBRID_KEX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Hybrid Mode Definitions
 * ======================================================================== */

/**
 * @brief Hybrid key exchange modes
 *
 * These modes determine how classical and post-quantum shared secrets
 * are combined to produce the final hybrid shared secret.
 */
typedef enum {
    HYBRID_MODE_CONCAT = 1,  /**< Concatenate shared secrets: classical_ss || pq_ss */
    HYBRID_MODE_XOR = 2      /**< XOR shared secrets: classical_ss XOR pq_ss (32 bytes) */
} pq_hybrid_mode_t;

/**
 * @brief Classical algorithm identifiers
 *
 * These identifiers specify which classical ECDH algorithm to use
 * in the hybrid key exchange.
 */
typedef enum {
    HYBRID_CLASSICAL_X25519 = 1,    /**< X25519 (Curve25519 ECDH) */
    HYBRID_CLASSICAL_P256 = 2       /**< ECDH with NIST P-256 curve */
} pq_hybrid_classical_t;

/* ========================================================================
 * Hybrid Key Exchange Context
 * ======================================================================== */

/**
 * @brief Hybrid key exchange context structure
 *
 * Maintains state for hybrid key exchange operations including algorithm
 * selection and combination mode.
 */
typedef struct pq_hybrid_kex_t {
    int classical_alg;  /**< Classical algorithm (HYBRID_CLASSICAL_*) */
    int pq_alg;         /**< PQ algorithm (PQ_KEM_MLKEM512/768/1024) */
    int mode;           /**< Hybrid mode (HYBRID_MODE_CONCAT or HYBRID_MODE_XOR) */
} pq_hybrid_kex_t;

/* ========================================================================
 * Hybrid Key Exchange Functions
 * ======================================================================== */

/**
 * @brief Initialize hybrid key exchange context
 *
 * Creates a new hybrid key exchange context with specified classical algorithm,
 * post-quantum algorithm, and combination mode.
 *
 * @param classical_alg Classical algorithm identifier (HYBRID_CLASSICAL_*)
 * @param pq_alg Post-quantum algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @param mode Hybrid mode (HYBRID_MODE_CONCAT or HYBRID_MODE_XOR)
 * @return Pointer to initialized context, or NULL on failure
 *
 * @note The returned context must be freed with pq_hybrid_kex_free()
 */
pq_hybrid_kex_t* pq_hybrid_kex_init(int classical_alg, int pq_alg, int mode);

/**
 * @brief Free hybrid key exchange context
 *
 * Securely clears and frees all memory associated with the context.
 *
 * @param kex Hybrid key exchange context to free (may be NULL)
 */
void pq_hybrid_kex_free(pq_hybrid_kex_t *kex);

/**
 * @brief Generate hybrid key pair
 *
 * Generates both classical and post-quantum key pairs. The public and secret
 * keys are concatenated: classical_key || pq_key
 *
 * @param kex Hybrid key exchange context
 * @param pk Output buffer for public key (must be pq_hybrid_kex_publickey_bytes() size)
 * @param pk_len Output parameter for actual public key length
 * @param sk Output buffer for secret key (must be pq_hybrid_kex_secretkey_bytes() size)
 * @param sk_len Output parameter for actual secret key length
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note Keys are concatenated: classical_pk || pq_pk and classical_sk || pq_sk
 */
int pq_hybrid_kex_keypair(pq_hybrid_kex_t *kex, uint8_t *pk, size_t *pk_len,
                          uint8_t *sk, size_t *sk_len);

/**
 * @brief Encapsulate shared secret (sender side)
 *
 * Performs both classical ECDH and post-quantum encapsulation, then combines
 * the results according to the hybrid mode.
 *
 * @param kex Hybrid key exchange context
 * @param ct Output buffer for ciphertext (must be pq_hybrid_kex_ciphertext_bytes() size)
 * @param ct_len Output parameter for actual ciphertext length
 * @param ss Output buffer for shared secret (must be pq_hybrid_kex_sharedsecret_bytes() size)
 * @param ss_len Output parameter for actual shared secret length
 * @param pk Recipient's public key (classical_pk || pq_pk)
 * @param pk_len Length of public key
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note Ciphertext is always concatenated: classical_ct || pq_ct
 *       Shared secret depends on mode:
 *       - CONCAT: classical_ss || pq_ss
 *       - XOR: classical_ss XOR pq_ss (32 bytes)
 */
int pq_hybrid_kex_encapsulate(pq_hybrid_kex_t *kex, uint8_t *ct, size_t *ct_len,
                              uint8_t *ss, size_t *ss_len,
                              const uint8_t *pk, size_t pk_len);

/**
 * @brief Decapsulate shared secret (receiver side)
 *
 * Performs both classical ECDH and post-quantum decapsulation, then combines
 * the results according to the hybrid mode.
 *
 * @param kex Hybrid key exchange context
 * @param ss Output buffer for shared secret (must be pq_hybrid_kex_sharedsecret_bytes() size)
 * @param ss_len Output parameter for actual shared secret length
 * @param ct Ciphertext from sender (classical_ct || pq_ct)
 * @param ct_len Length of ciphertext
 * @param sk Recipient's secret key (classical_sk || pq_sk)
 * @param sk_len Length of secret key
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note Shared secret depends on mode:
 *       - CONCAT: classical_ss || pq_ss
 *       - XOR: classical_ss XOR pq_ss (32 bytes)
 */
int pq_hybrid_kex_decapsulate(pq_hybrid_kex_t *kex, uint8_t *ss, size_t *ss_len,
                              const uint8_t *ct, size_t ct_len,
                              const uint8_t *sk, size_t sk_len);

/* ========================================================================
 * Size Query Functions
 * ======================================================================== */

/**
 * @brief Get public key size for hybrid key exchange
 *
 * @param kex Hybrid key exchange context
 * @return Public key size in bytes (classical_pk_size + pq_pk_size)
 */
size_t pq_hybrid_kex_publickey_bytes(pq_hybrid_kex_t *kex);

/**
 * @brief Get secret key size for hybrid key exchange
 *
 * @param kex Hybrid key exchange context
 * @return Secret key size in bytes (classical_sk_size + pq_sk_size)
 */
size_t pq_hybrid_kex_secretkey_bytes(pq_hybrid_kex_t *kex);

/**
 * @brief Get ciphertext size for hybrid key exchange
 *
 * @param kex Hybrid key exchange context
 * @return Ciphertext size in bytes (classical_ct_size + pq_ct_size)
 */
size_t pq_hybrid_kex_ciphertext_bytes(pq_hybrid_kex_t *kex);

/**
 * @brief Get shared secret size for hybrid key exchange
 *
 * @param kex Hybrid key exchange context
 * @return Shared secret size in bytes
 *         - CONCAT mode: classical_ss_size + pq_ss_size
 *         - XOR mode: 32 bytes (fixed)
 */
size_t pq_hybrid_kex_sharedsecret_bytes(pq_hybrid_kex_t *kex);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_KEX_H */
