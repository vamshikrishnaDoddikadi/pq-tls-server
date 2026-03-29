/**
 * @file pq_kem.c
 * @brief ML-KEM (Kyber) Key Encapsulation Mechanism implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements ML-KEM key encapsulation using the liboqs library.
 * ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) is standardized
 * as FIPS 203 and provides quantum-resistant key exchange.
 */

#include "pq_kem.h"
#include "pq_errors.h"
#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ========================================================================
 * Algorithm Name Mapping
 * ======================================================================== */

/**
 * @brief Get OQS algorithm name for ML-KEM variant
 *
 * Maps internal algorithm identifiers to liboqs algorithm name strings.
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Algorithm name string for liboqs, or NULL if invalid
 */
const char* pq_kem_algorithm_name(int algorithm) {
    switch (algorithm) {
        case PQ_KEM_MLKEM512:
            return "ML-KEM-512";
        case PQ_KEM_MLKEM768:
            return "ML-KEM-768";
        case PQ_KEM_MLKEM1024:
            return "ML-KEM-1024";
        default:
            return NULL;
    }
}

/* ========================================================================
 * ML-KEM Size Query Functions
 * ======================================================================== */

/**
 * @brief Get public key size for ML-KEM algorithm
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Public key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_kem_publickey_bytes(int algorithm) {
    switch (algorithm) {
        case PQ_KEM_MLKEM512:
            return PQ_KEM_MLKEM512_PUBLICKEY_BYTES;
        case PQ_KEM_MLKEM768:
            return PQ_KEM_MLKEM768_PUBLICKEY_BYTES;
        case PQ_KEM_MLKEM1024:
            return PQ_KEM_MLKEM1024_PUBLICKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get secret key size for ML-KEM algorithm
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Secret key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_kem_secretkey_bytes(int algorithm) {
    switch (algorithm) {
        case PQ_KEM_MLKEM512:
            return PQ_KEM_MLKEM512_SECRETKEY_BYTES;
        case PQ_KEM_MLKEM768:
            return PQ_KEM_MLKEM768_SECRETKEY_BYTES;
        case PQ_KEM_MLKEM1024:
            return PQ_KEM_MLKEM1024_SECRETKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get ciphertext size for ML-KEM algorithm
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Ciphertext size in bytes, or 0 if algorithm is invalid
 */
size_t pq_kem_ciphertext_bytes(int algorithm) {
    switch (algorithm) {
        case PQ_KEM_MLKEM512:
            return PQ_KEM_MLKEM512_CIPHERTEXT_BYTES;
        case PQ_KEM_MLKEM768:
            return PQ_KEM_MLKEM768_CIPHERTEXT_BYTES;
        case PQ_KEM_MLKEM1024:
            return PQ_KEM_MLKEM1024_CIPHERTEXT_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get shared secret size for ML-KEM algorithm
 *
 * All ML-KEM variants produce 32-byte shared secrets.
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Shared secret size in bytes (32), or 0 if algorithm is invalid
 */
size_t pq_kem_sharedsecret_bytes(int algorithm) {
    switch (algorithm) {
        case PQ_KEM_MLKEM512:
            return PQ_KEM_MLKEM512_SHAREDSECRET_BYTES;
        case PQ_KEM_MLKEM768:
            return PQ_KEM_MLKEM768_SHAREDSECRET_BYTES;
        case PQ_KEM_MLKEM1024:
            return PQ_KEM_MLKEM1024_SHAREDSECRET_BYTES;
        default:
            return 0;
    }
}

/* ========================================================================
 * ML-KEM Core Operations
 * ======================================================================== */

/**
 * @brief Generate ML-KEM key pair
 *
 * Generates a public/secret key pair using the specified ML-KEM algorithm.
 * Uses liboqs OQS_KEM_keypair() for cryptographically secure key generation.
 *
 * @param algorithm ML-KEM algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @param pk Output buffer for public key (must be pq_kem_publickey_bytes() size)
 * @param sk Output buffer for secret key (must be pq_kem_secretkey_bytes() size)
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_kem_keypair(int algorithm, uint8_t *pk, uint8_t *sk) {
    /* Validate input parameters */
    if (pk == NULL || sk == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Get algorithm name for liboqs */
    const char *alg_name = pq_kem_algorithm_name(algorithm);
    if (alg_name == NULL) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Initialize OQS KEM context */
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Generate key pair */
    OQS_STATUS status = OQS_KEM_keypair(kem, pk, sk);
    
    /* Clean up OQS resources */
    OQS_KEM_free(kem);
    
    /* Check result and clear sensitive data on error */
    if (status != OQS_SUCCESS) {
        OPENSSL_cleanse(sk, pq_kem_secretkey_bytes(algorithm));
        return PQ_ERR_KEY_GENERATION_FAILED;
    }
    
    return PQ_SUCCESS;
}

/**
 * @brief Encapsulate shared secret with ML-KEM
 *
 * Generates a random shared secret and encapsulates it using the recipient's
 * public key. Uses liboqs OQS_KEM_encaps() for secure encapsulation.
 *
 * @param algorithm ML-KEM algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @param ct Output buffer for ciphertext (must be pq_kem_ciphertext_bytes() size)
 * @param ss Output buffer for shared secret (must be pq_kem_sharedsecret_bytes() size)
 * @param pk Recipient's public key
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_kem_encapsulate(int algorithm, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    /* Validate input parameters */
    if (ct == NULL || ss == NULL || pk == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Get algorithm name for liboqs */
    const char *alg_name = pq_kem_algorithm_name(algorithm);
    if (alg_name == NULL) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Initialize OQS KEM context */
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Encapsulate shared secret */
    OQS_STATUS status = OQS_KEM_encaps(kem, ct, ss, pk);
    
    /* Clean up OQS resources */
    OQS_KEM_free(kem);
    
    /* Check result and clear sensitive data on error */
    if (status != OQS_SUCCESS) {
        OPENSSL_cleanse(ss, pq_kem_sharedsecret_bytes(algorithm));
        return PQ_ERR_ENCRYPTION_FAILED;
    }
    
    return PQ_SUCCESS;
}

/**
 * @brief Decapsulate shared secret with ML-KEM
 *
 * Recovers the shared secret from a ciphertext using the recipient's secret key.
 * Uses liboqs OQS_KEM_decaps() for secure decapsulation.
 *
 * @param algorithm ML-KEM algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @param ss Output buffer for shared secret (must be pq_kem_sharedsecret_bytes() size)
 * @param ct Ciphertext containing encapsulated shared secret
 * @param sk Recipient's secret key
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_kem_decapsulate(int algorithm, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    /* Validate input parameters */
    if (ss == NULL || ct == NULL || sk == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Get algorithm name for liboqs */
    const char *alg_name = pq_kem_algorithm_name(algorithm);
    if (alg_name == NULL) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Initialize OQS KEM context */
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Decapsulate shared secret */
    OQS_STATUS status = OQS_KEM_decaps(kem, ss, ct, sk);
    
    /* Clean up OQS resources */
    OQS_KEM_free(kem);
    
    /* Check result and clear sensitive data on error */
    if (status != OQS_SUCCESS) {
        OPENSSL_cleanse(ss, pq_kem_sharedsecret_bytes(algorithm));
        return PQ_ERR_DECRYPTION_FAILED;
    }
    
    return PQ_SUCCESS;
}
