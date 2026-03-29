/**
 * @file pq_sig.h
 * @brief ML-DSA (Dilithium) Digital Signatures for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module provides ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
 * support for post-quantum TLS. ML-DSA is standardized as FIPS 204 and provides
 * quantum-resistant digital signatures for authentication and integrity.
 *
 * Supported algorithms:
 * - ML-DSA-44: NIST Security Level 2 (128-bit classical, quantum-resistant)
 * - ML-DSA-65: NIST Security Level 3 (192-bit classical, quantum-resistant)
 * - ML-DSA-87: NIST Security Level 5 (256-bit classical, quantum-resistant)
 * - Ed25519: Classical EdDSA (128-bit security)
 * - ECDSA P-256: Classical ECDSA (128-bit security)
 * - RSA-2048: Classical RSA (112-bit security)
 */

#ifndef PQ_SIG_H
#define PQ_SIG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Signature Algorithm Identifiers
 * ======================================================================== */

/**
 * @brief Signature algorithm enumeration
 *
 * These identifiers map to both post-quantum (ML-DSA) and classical
 * signature algorithms for hybrid and fallback scenarios.
 */
typedef enum {
    /* ML-DSA (Post-Quantum) Algorithms */
    PQ_SIG_MLDSA44 = 0,     /**< ML-DSA-44 (NIST Level 2, quantum-resistant) */
    PQ_SIG_MLDSA65 = 1,     /**< ML-DSA-65 (NIST Level 3, quantum-resistant) */
    PQ_SIG_MLDSA87 = 2,     /**< ML-DSA-87 (NIST Level 5, quantum-resistant) */
    
    /* Classical Fallback Algorithms */
    PQ_SIG_ED25519 = 100,   /**< Ed25519 (128-bit classical security) */
    PQ_SIG_ECDSA_P256 = 101, /**< ECDSA P-256 (128-bit classical security) */
    PQ_SIG_RSA2048 = 102    /**< RSA-2048 (112-bit classical security) */
} pq_sig_algorithm_t;

/* ========================================================================
 * ML-DSA Key and Signature Sizes (FIPS 204)
 * ======================================================================== */

/* ML-DSA-44 sizes (NIST Level 2) */
#define PQ_SIG_MLDSA44_PUBLICKEY_BYTES  1312  /**< Public key size */
#define PQ_SIG_MLDSA44_SECRETKEY_BYTES  2560  /**< Secret key size */
#define PQ_SIG_MLDSA44_SIGNATURE_BYTES  2420  /**< Signature size */

/* ML-DSA-65 sizes (NIST Level 3) */
#define PQ_SIG_MLDSA65_PUBLICKEY_BYTES  1952  /**< Public key size */
#define PQ_SIG_MLDSA65_SECRETKEY_BYTES  4032  /**< Secret key size */
#define PQ_SIG_MLDSA65_SIGNATURE_BYTES  3309  /**< Signature size */

/* ML-DSA-87 sizes (NIST Level 5) */
#define PQ_SIG_MLDSA87_PUBLICKEY_BYTES  2592  /**< Public key size */
#define PQ_SIG_MLDSA87_SECRETKEY_BYTES  4896  /**< Secret key size */
#define PQ_SIG_MLDSA87_SIGNATURE_BYTES  4627  /**< Signature size */

/* Classical algorithm sizes */
#define PQ_SIG_ED25519_PUBLICKEY_BYTES  32    /**< Ed25519 public key size */
#define PQ_SIG_ED25519_SECRETKEY_BYTES  32    /**< Ed25519 secret key size */
#define PQ_SIG_ED25519_SIGNATURE_BYTES  64    /**< Ed25519 signature size */

#define PQ_SIG_ECDSA_P256_PUBLICKEY_BYTES  65   /**< ECDSA P-256 public key size (uncompressed) */
#define PQ_SIG_ECDSA_P256_SECRETKEY_BYTES  32   /**< ECDSA P-256 secret key size */
#define PQ_SIG_ECDSA_P256_SIGNATURE_BYTES  72   /**< ECDSA P-256 max signature size (DER) */

#define PQ_SIG_RSA2048_PUBLICKEY_BYTES  294   /**< RSA-2048 public key size (DER) */
#define PQ_SIG_RSA2048_SECRETKEY_BYTES  1192  /**< RSA-2048 secret key size (DER) */
#define PQ_SIG_RSA2048_SIGNATURE_BYTES  256   /**< RSA-2048 signature size */

/* ========================================================================
 * Signature Core Operations
 * ======================================================================== */

/**
 * @brief Generate signature key pair
 *
 * Generates a public/secret key pair for the specified signature algorithm.
 * The keys can be used for signing and verification operations.
 *
 * @param algorithm Signature algorithm identifier (PQ_SIG_MLDSA* or PQ_SIG_*)
 * @param pk Output buffer for public key (must be pq_sig_publickey_bytes() size)
 * @param sk Output buffer for secret key (must be pq_sig_secretkey_bytes() size)
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note Buffers must be pre-allocated with sufficient size for the algorithm.
 *       Use pq_sig_publickey_bytes() and pq_sig_secretkey_bytes() to determine sizes.
 */
int pq_sig_keypair(int algorithm, uint8_t *pk, uint8_t *sk);

/**
 * @brief Sign a message
 *
 * Generates a digital signature for a message using the signer's secret key.
 * The signature can be verified by anyone with the corresponding public key.
 *
 * @param algorithm Signature algorithm identifier (PQ_SIG_MLDSA* or PQ_SIG_*)
 * @param sig Output buffer for signature (must be pq_sig_signature_bytes() size)
 * @param sig_len Output parameter for actual signature length
 * @param msg Message to sign
 * @param msg_len Length of message in bytes
 * @param sk Signer's secret key
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note The actual signature length may be less than the maximum for some algorithms.
 *       Always check sig_len after successful signing.
 */
int pq_sig_sign(int algorithm, uint8_t *sig, size_t *sig_len,
                const uint8_t *msg, size_t msg_len, const uint8_t *sk);

/**
 * @brief Verify a signature
 *
 * Verifies that a signature is valid for a given message and public key.
 * Returns success only if the signature is cryptographically valid.
 *
 * @param algorithm Signature algorithm identifier (PQ_SIG_MLDSA* or PQ_SIG_*)
 * @param msg Message that was signed
 * @param msg_len Length of message in bytes
 * @param sig Signature to verify
 * @param sig_len Length of signature in bytes
 * @param pk Signer's public key
 * @return PQ_SUCCESS if signature is valid, error code otherwise
 *
 * @note Verification failure returns PQ_ERR_VERIFICATION_FAILED, not PQ_SUCCESS.
 */
int pq_sig_verify(int algorithm, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len, const uint8_t *pk);

/* ========================================================================
 * Signature Size Query Functions
 * ======================================================================== */

/**
 * @brief Get public key size for signature algorithm
 *
 * @param algorithm Signature algorithm identifier
 * @return Public key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_sig_publickey_bytes(int algorithm);

/**
 * @brief Get secret key size for signature algorithm
 *
 * @param algorithm Signature algorithm identifier
 * @return Secret key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_sig_secretkey_bytes(int algorithm);

/**
 * @brief Get maximum signature size for algorithm
 *
 * @param algorithm Signature algorithm identifier
 * @return Maximum signature size in bytes, or 0 if algorithm is invalid
 *
 * @note Actual signature length may be smaller. Check sig_len after signing.
 */
size_t pq_sig_signature_bytes(int algorithm);

/* ========================================================================
 * Algorithm Information Functions
 * ======================================================================== */

/**
 * @brief Get algorithm name string
 *
 * Returns the standardized algorithm name for use with liboqs or OpenSSL.
 *
 * @param algorithm Signature algorithm identifier
 * @return Algorithm name string, or NULL if algorithm is invalid
 */
const char* pq_sig_algorithm_name(int algorithm);

/**
 * @brief Get NIST security level for algorithm
 *
 * Returns the NIST security level (1, 2, 3, or 5) for the algorithm.
 * Classical algorithms return equivalent security levels.
 *
 * @param algorithm Signature algorithm identifier
 * @return NIST security level (1-5), or 0 if algorithm is invalid
 *
 * @note Security levels:
 *       - Level 1: 128-bit classical security (AES-128 equivalent)
 *       - Level 2: 128-bit quantum-resistant (ML-DSA-44)
 *       - Level 3: 192-bit security (AES-192 equivalent, ML-DSA-65)
 *       - Level 5: 256-bit security (AES-256 equivalent, ML-DSA-87)
 */
int pq_sig_security_level(int algorithm);

#ifdef __cplusplus
}
#endif

#endif /* PQ_SIG_H */
