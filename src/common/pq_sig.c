/**
 * @file pq_sig.c
 * @brief ML-DSA (Dilithium) Digital Signatures implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements ML-DSA digital signatures using the liboqs library
 * and classical signature algorithms using OpenSSL 3.0. ML-DSA (Module-Lattice-Based
 * Digital Signature Algorithm) is standardized as FIPS 204 and provides
 * quantum-resistant digital signatures.
 */

#include "pq_sig.h"
#include "pq_errors.h"
#include "kem_classical.h"   /* raw P-256 key helpers (EVP_PKEY_fromdata based) */
#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

_Static_assert(PQ_SIG_ECDSA_P256_PUBLICKEY_BYTES == PQ_P256_PUBLICKEY_BYTES,
               "P-256 public key size mismatch");
_Static_assert(PQ_SIG_ECDSA_P256_SECRETKEY_BYTES == PQ_P256_SECRETKEY_BYTES,
               "P-256 secret key size mismatch");

/* ========================================================================
 * Algorithm Name Mapping
 * ======================================================================== */

/**
 * @brief Get algorithm name for signature variant
 *
 * Maps internal algorithm identifiers to liboqs or OpenSSL algorithm name strings.
 *
 * @param algorithm Signature algorithm identifier
 * @return Algorithm name string, or NULL if invalid
 */
const char* pq_sig_algorithm_name(int algorithm) {
    switch (algorithm) {
        /* ML-DSA (Post-Quantum) */
        case PQ_SIG_MLDSA44:
            return "ML-DSA-44";
        case PQ_SIG_MLDSA65:
            return "ML-DSA-65";
        case PQ_SIG_MLDSA87:
            return "ML-DSA-87";
        
        /* Classical Fallbacks */
        case PQ_SIG_ED25519:
            return "Ed25519";
        case PQ_SIG_ECDSA_P256:
            return "ECDSA-P256";
        case PQ_SIG_RSA2048:
            return "RSA-2048";
        
        default:
            return NULL;
    }
}

/**
 * @brief Get NIST security level for algorithm
 *
 * @param algorithm Signature algorithm identifier
 * @return NIST security level (1-5), or 0 if algorithm is invalid
 */
int pq_sig_security_level(int algorithm) {
    switch (algorithm) {
        case PQ_SIG_MLDSA44:
            return 2;  /* NIST Level 2 (quantum-resistant) */
        case PQ_SIG_MLDSA65:
            return 3;  /* NIST Level 3 */
        case PQ_SIG_MLDSA87:
            return 5;  /* NIST Level 5 */
        case PQ_SIG_ED25519:
        case PQ_SIG_ECDSA_P256:
            return 1;  /* 128-bit classical security */
        case PQ_SIG_RSA2048:
            return 1;  /* ~112-bit security, rounded to Level 1 */
        default:
            return 0;
    }
}

/* ========================================================================
 * Signature Size Query Functions
 * ======================================================================== */

/**
 * @brief Get public key size for signature algorithm
 *
 * @param algorithm Signature algorithm identifier
 * @return Public key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_sig_publickey_bytes(int algorithm) {
    switch (algorithm) {
        case PQ_SIG_MLDSA44:
            return PQ_SIG_MLDSA44_PUBLICKEY_BYTES;
        case PQ_SIG_MLDSA65:
            return PQ_SIG_MLDSA65_PUBLICKEY_BYTES;
        case PQ_SIG_MLDSA87:
            return PQ_SIG_MLDSA87_PUBLICKEY_BYTES;
        case PQ_SIG_ED25519:
            return PQ_SIG_ED25519_PUBLICKEY_BYTES;
        case PQ_SIG_ECDSA_P256:
            return PQ_SIG_ECDSA_P256_PUBLICKEY_BYTES;
        case PQ_SIG_RSA2048:
            return PQ_SIG_RSA2048_PUBLICKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get secret key size for signature algorithm
 *
 * @param algorithm Signature algorithm identifier
 * @return Secret key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_sig_secretkey_bytes(int algorithm) {
    switch (algorithm) {
        case PQ_SIG_MLDSA44:
            return PQ_SIG_MLDSA44_SECRETKEY_BYTES;
        case PQ_SIG_MLDSA65:
            return PQ_SIG_MLDSA65_SECRETKEY_BYTES;
        case PQ_SIG_MLDSA87:
            return PQ_SIG_MLDSA87_SECRETKEY_BYTES;
        case PQ_SIG_ED25519:
            return PQ_SIG_ED25519_SECRETKEY_BYTES;
        case PQ_SIG_ECDSA_P256:
            return PQ_SIG_ECDSA_P256_SECRETKEY_BYTES;
        case PQ_SIG_RSA2048:
            return PQ_SIG_RSA2048_SECRETKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get maximum signature size for algorithm
 *
 * @param algorithm Signature algorithm identifier
 * @return Maximum signature size in bytes, or 0 if algorithm is invalid
 */
size_t pq_sig_signature_bytes(int algorithm) {
    switch (algorithm) {
        case PQ_SIG_MLDSA44:
            return PQ_SIG_MLDSA44_SIGNATURE_BYTES;
        case PQ_SIG_MLDSA65:
            return PQ_SIG_MLDSA65_SIGNATURE_BYTES;
        case PQ_SIG_MLDSA87:
            return PQ_SIG_MLDSA87_SIGNATURE_BYTES;
        case PQ_SIG_ED25519:
            return PQ_SIG_ED25519_SIGNATURE_BYTES;
        case PQ_SIG_ECDSA_P256:
            return PQ_SIG_ECDSA_P256_SIGNATURE_BYTES;
        case PQ_SIG_RSA2048:
            return PQ_SIG_RSA2048_SIGNATURE_BYTES;
        default:
            return 0;
    }
}

/* ========================================================================
 * ML-DSA (liboqs) Implementation
 * ======================================================================== */

/**
 * @brief OQS_SIG_new() plus a check that liboqs's sizes match pq_sig.h
 *
 * Callers size buffers from the PQ_SIG_MLDSA* constants; if the linked
 * liboqs ever disagrees, operating would overflow those buffers.
 */
static OQS_SIG *pq_sig_new_checked(int algorithm) {
    const char *alg_name = pq_sig_algorithm_name(algorithm);
    if (!alg_name) return NULL;

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) return NULL;

    if (sig->length_public_key != pq_sig_publickey_bytes(algorithm) ||
        sig->length_secret_key != pq_sig_secretkey_bytes(algorithm) ||
        sig->length_signature != pq_sig_signature_bytes(algorithm)) {
        OQS_SIG_free(sig);
        return NULL;
    }
    return sig;
}

static int pq_sig_keypair_mldsa(int algorithm, uint8_t *pk, uint8_t *sk) {
    OQS_SIG *sig = pq_sig_new_checked(algorithm);
    if (!sig) return PQ_ERR_CRYPTO_FAILED;
    
    OQS_STATUS status = OQS_SIG_keypair(sig, pk, sk);
    OQS_SIG_free(sig);
    
    /* Check result and clear sensitive data on error */
    if (status != OQS_SUCCESS) {
        OPENSSL_cleanse(sk, pq_sig_secretkey_bytes(algorithm));
        return PQ_ERR_KEY_GENERATION_FAILED;
    }
    
    return PQ_SUCCESS;
}

static int pq_sig_sign_mldsa(int algorithm, uint8_t *sig, size_t capacity, size_t *out_len,
                             const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    OQS_SIG *oqs_sig = pq_sig_new_checked(algorithm);
    if (!oqs_sig) return PQ_ERR_CRYPTO_FAILED;
    
    /* liboqs writes up to length_signature bytes and ignores *out_len on input */
    if (capacity < oqs_sig->length_signature) {
        OQS_SIG_free(oqs_sig);
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    size_t len = 0;
    OQS_STATUS status = OQS_SIG_sign(oqs_sig, sig, &len, msg, msg_len, sk);
    size_t max_len = oqs_sig->length_signature;
    OQS_SIG_free(oqs_sig);

    if (status != OQS_SUCCESS || len == 0 || len > max_len) {
        return PQ_ERR_SIGNATURE_FAILED;
    }
    
    *out_len = len;
    return PQ_SUCCESS;
}

static int pq_sig_verify_mldsa(int algorithm, const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    OQS_SIG *oqs_sig = pq_sig_new_checked(algorithm);
    if (!oqs_sig) return PQ_ERR_CRYPTO_FAILED;
    
    OQS_STATUS status = OQS_SIG_verify(oqs_sig, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(oqs_sig);
    
    return (status == OQS_SUCCESS) ? PQ_SUCCESS : PQ_ERR_VERIFICATION_FAILED;
}

/* ========================================================================
 * Generic EVP sign / verify helpers
 * ======================================================================== */

/* md == NULL for Ed25519 (one-shot, no pre-hash) */
static int evp_sign(EVP_PKEY *pkey, const EVP_MD *md,
                    uint8_t *sig, size_t capacity, size_t *out_len,
                    const uint8_t *msg, size_t msg_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t len = capacity;   /* EVP_DigestSign treats *siglen as the buffer size */
    int rc = PQ_ERR_SIGNATURE_FAILED;

    if (!md_ctx) return PQ_ERR_MEMORY_ALLOCATION;
    if (EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey) <= 0) goto done;
    if (EVP_DigestSign(md_ctx, sig, &len, msg, msg_len) <= 0) goto done;
    if (len == 0 || len > capacity) goto done;
    *out_len = len;
    rc = PQ_SUCCESS;

done:
    EVP_MD_CTX_free(md_ctx);
    return rc;
}

static int evp_verify(EVP_PKEY *pkey, const EVP_MD *md,
                      const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg, size_t msg_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    int rc = PQ_ERR_VERIFICATION_FAILED;

    if (!md_ctx) return PQ_ERR_MEMORY_ALLOCATION;
    if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pkey) <= 0) {
        rc = PQ_ERR_CRYPTO_FAILED;
        goto done;
    }
    if (EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len) == 1) rc = PQ_SUCCESS;

done:
    EVP_MD_CTX_free(md_ctx);
    return rc;
}

/* ========================================================================
 * Ed25519 (OpenSSL) Implementation
 * ======================================================================== */

static int pq_sig_keypair_ed25519(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *pkey = NULL;
    size_t pk_len = PQ_SIG_ED25519_PUBLICKEY_BYTES, sk_len = PQ_SIG_ED25519_SECRETKEY_BYTES;
    int rc = PQ_ERR_KEY_GENERATION_FAILED;

    if (!ctx) return PQ_ERR_CRYPTO_FAILED;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto done;

    /* Extract raw keys (32 bytes each for Ed25519) */
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0 ||
        pk_len != PQ_SIG_ED25519_PUBLICKEY_BYTES) goto done;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0 ||
        sk_len != PQ_SIG_ED25519_SECRETKEY_BYTES) goto done;
    rc = PQ_SUCCESS;

done:
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(sk, PQ_SIG_ED25519_SECRETKEY_BYTES);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int pq_sig_sign_ed25519(uint8_t *sig, size_t capacity, size_t *out_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sk) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk,
                                                  PQ_SIG_ED25519_SECRETKEY_BYTES);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;

    int rc = evp_sign(pkey, NULL, sig, capacity, out_len, msg, msg_len);
    EVP_PKEY_free(pkey);
    if (rc == PQ_SUCCESS && *out_len != PQ_SIG_ED25519_SIGNATURE_BYTES)
        rc = PQ_ERR_SIGNATURE_FAILED;
    return rc;
}

static int pq_sig_verify_ed25519(const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len,
                                 const uint8_t *pk) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk,
                                                 PQ_SIG_ED25519_PUBLICKEY_BYTES);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;

    int rc = evp_verify(pkey, NULL, sig, sig_len, msg, msg_len);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ========================================================================
 * ECDSA P-256 (OpenSSL) Implementation
 *
 * Raw keys: pk = uncompressed point (65 bytes), sk = 32-byte scalar.
 * Built with EVP_PKEY_fromdata / OSSL_PARAM (kem_classical.c helpers);
 * no deprecated EC_KEY APIs.
 * ======================================================================== */

static int pq_sig_keypair_ecdsa_p256(uint8_t *pk, uint8_t *sk) {
    return pq_p256_generate_raw(pk, sk);
}

static int pq_sig_sign_ecdsa_p256(uint8_t *sig, size_t capacity, size_t *out_len,
                                  const uint8_t *msg, size_t msg_len,
                                  const uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    int rc = pq_p256_pkey_from_private(sk, &pkey);
    if (rc != PQ_SUCCESS) return PQ_ERR_CRYPTO_FAILED;

    rc = evp_sign(pkey, EVP_sha256(), sig, capacity, out_len, msg, msg_len);
    EVP_PKEY_free(pkey);
    return rc;
}

static int pq_sig_verify_ecdsa_p256(const uint8_t *msg, size_t msg_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const uint8_t *pk) {
    EVP_PKEY *pkey = NULL;
    /* Validates encoding and that the point is on the curve */
    int rc = pq_p256_pkey_from_public(pk, &pkey);
    if (rc != PQ_SUCCESS) return PQ_ERR_VERIFICATION_FAILED;

    rc = evp_verify(pkey, EVP_sha256(), sig, sig_len, msg, msg_len);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ========================================================================
 * RSA-2048 (OpenSSL) Implementation
 * ======================================================================== */

static int pq_sig_keypair_rsa2048(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    unsigned char *pk_der = NULL, *sk_der = NULL;
    int pk_len = 0, sk_len = 0;
    int rc = PQ_ERR_KEY_GENERATION_FAILED;

    if (!ctx) return PQ_ERR_CRYPTO_FAILED;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto done;
    
    /* Serialize keys to DER format */
    pk_len = i2d_PUBKEY(pkey, &pk_der);
    sk_len = i2d_PrivateKey(pkey, &sk_der);
    if (pk_len <= 0 || sk_len <= 0 ||
        pk_len > (int)PQ_SIG_RSA2048_PUBLICKEY_BYTES ||
        sk_len > (int)PQ_SIG_RSA2048_SECRETKEY_BYTES) {
        goto done;
    }
    
    /* Copy to output buffers and zero the remaining space */
    memcpy(pk, pk_der, (size_t)pk_len);
    memcpy(sk, sk_der, (size_t)sk_len);
    memset(pk + pk_len, 0, PQ_SIG_RSA2048_PUBLICKEY_BYTES - (size_t)pk_len);
    memset(sk + sk_len, 0, PQ_SIG_RSA2048_SECRETKEY_BYTES - (size_t)sk_len);
    rc = PQ_SUCCESS;

done:
    OPENSSL_free(pk_der);
    /* The private key DER must be wiped, not just freed */
    if (sk_der) OPENSSL_clear_free(sk_der, sk_len > 0 ? (size_t)sk_len : 0);
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(sk, PQ_SIG_RSA2048_SECRETKEY_BYTES);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int pq_sig_sign_rsa2048(uint8_t *sig, size_t capacity, size_t *out_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sk) {
    /* Parse private key from DER format (trailing zero padding is ignored) */
    const unsigned char *sk_ptr = sk;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &sk_ptr, PQ_SIG_RSA2048_SECRETKEY_BYTES);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;

    int rc = evp_sign(pkey, EVP_sha256(), sig, capacity, out_len, msg, msg_len);
    EVP_PKEY_free(pkey);
    return rc;
}

static int pq_sig_verify_rsa2048(const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len,
                                 const uint8_t *pk) {
    /* Parse public key from DER format */
    const unsigned char *pk_ptr = pk;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &pk_ptr, PQ_SIG_RSA2048_PUBLICKEY_BYTES);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;

    int rc = evp_verify(pkey, EVP_sha256(), sig, sig_len, msg, msg_len);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ========================================================================
 * Main API Functions (Algorithm Dispatch)
 * ======================================================================== */

/**
 * @brief Generate signature key pair
 *
 * Dispatches to appropriate implementation based on algorithm type.
 *
 * @param algorithm Signature algorithm identifier
 * @param pk Output buffer for public key
 * @param sk Output buffer for secret key
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_sig_keypair(int algorithm, uint8_t *pk, uint8_t *sk) {
    /* Validate input parameters */
    if (pk == NULL || sk == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Dispatch to appropriate implementation */
    switch (algorithm) {
        /* ML-DSA (Post-Quantum) */
        case PQ_SIG_MLDSA44:
        case PQ_SIG_MLDSA65:
        case PQ_SIG_MLDSA87:
            return pq_sig_keypair_mldsa(algorithm, pk, sk);
        
        /* Classical Fallbacks */
        case PQ_SIG_ED25519:
            return pq_sig_keypair_ed25519(pk, sk);
        case PQ_SIG_ECDSA_P256:
            return pq_sig_keypair_ecdsa_p256(pk, sk);
        case PQ_SIG_RSA2048:
            return pq_sig_keypair_rsa2048(pk, sk);
        
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
}

/**
 * @brief Sign a message
 *
 * Dispatches to appropriate implementation based on algorithm type.
 *
 * @param algorithm Signature algorithm identifier
 * @param sig Output buffer for signature
 * @param sig_len Output parameter for actual signature length
 * @param msg Message to sign
 * @param msg_len Length of message in bytes
 * @param sk Signer's secret key
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_sig_sign(int algorithm, uint8_t *sig, size_t *sig_len,
                const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    /* Validate input parameters */
    if (sig == NULL || sig_len == NULL || msg == NULL || sk == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    size_t max_len = pq_sig_signature_bytes(algorithm);
    if (max_len == 0) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* *sig_len carries the buffer capacity on input */
    size_t capacity = *sig_len;
    if (capacity < max_len) {
        *sig_len = 0;
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    size_t out_len = 0;
    int rc;
    
    /* Dispatch to appropriate implementation */
    switch (algorithm) {
        /* ML-DSA (Post-Quantum) */
        case PQ_SIG_MLDSA44:
        case PQ_SIG_MLDSA65:
        case PQ_SIG_MLDSA87:
            rc = pq_sig_sign_mldsa(algorithm, sig, capacity, &out_len, msg, msg_len, sk);
            break;
        
        /* Classical Fallbacks */
        case PQ_SIG_ED25519:
            rc = pq_sig_sign_ed25519(sig, capacity, &out_len, msg, msg_len, sk);
            break;
        case PQ_SIG_ECDSA_P256:
            rc = pq_sig_sign_ecdsa_p256(sig, capacity, &out_len, msg, msg_len, sk);
            break;
        case PQ_SIG_RSA2048:
            rc = pq_sig_sign_rsa2048(sig, capacity, &out_len, msg, msg_len, sk);
            break;
        
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
    
    if (rc != PQ_SUCCESS) {
        /* Clear any partial signature (bounded by the known maximum) */
        OPENSSL_cleanse(sig, max_len);
        *sig_len = 0;
        return rc;
    }
    
    *sig_len = out_len;
    return PQ_SUCCESS;
}

/**
 * @brief Verify a signature
 *
 * Dispatches to appropriate implementation based on algorithm type.
 *
 * @param algorithm Signature algorithm identifier
 * @param msg Message that was signed
 * @param msg_len Length of message in bytes
 * @param sig Signature to verify
 * @param sig_len Length of signature in bytes
 * @param pk Signer's public key
 * @return PQ_SUCCESS if signature is valid, error code otherwise
 */
int pq_sig_verify(int algorithm, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    /* Validate input parameters */
    if (msg == NULL || sig == NULL || pk == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Dispatch to appropriate implementation */
    switch (algorithm) {
        /* ML-DSA (Post-Quantum) */
        case PQ_SIG_MLDSA44:
        case PQ_SIG_MLDSA65:
        case PQ_SIG_MLDSA87:
            return pq_sig_verify_mldsa(algorithm, msg, msg_len, sig, sig_len, pk);
        
        /* Classical Fallbacks */
        case PQ_SIG_ED25519:
            return pq_sig_verify_ed25519(msg, msg_len, sig, sig_len, pk);
        case PQ_SIG_ECDSA_P256:
            return pq_sig_verify_ecdsa_p256(msg, msg_len, sig, sig_len, pk);
        case PQ_SIG_RSA2048:
            return pq_sig_verify_rsa2048(msg, msg_len, sig, sig_len, pk);
        
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
}

/* ========================================================================
 * Self test
 * ======================================================================== */

int pq_sig_self_test(int algorithm) {
    size_t pk_size = pq_sig_publickey_bytes(algorithm);
    size_t sk_size = pq_sig_secretkey_bytes(algorithm);
    size_t sig_size = pq_sig_signature_bytes(algorithm);
    if (pk_size == 0 || sk_size == 0 || sig_size == 0) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* ML-DSA: the backend must exist and agree with our size constants */
    if (algorithm == PQ_SIG_MLDSA44 || algorithm == PQ_SIG_MLDSA65 ||
        algorithm == PQ_SIG_MLDSA87) {
        OQS_SIG *probe = pq_sig_new_checked(algorithm);
        if (!probe) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;
        OQS_SIG_free(probe);
    }
    
    static const uint8_t msg[] = "pq-tls signature self-test";
    uint8_t *pk = malloc(pk_size);
    uint8_t *sk = malloc(sk_size);
    uint8_t *sig = malloc(sig_size);
    size_t sig_len = sig_size;
    int rc = PQ_ERR_MEMORY_ALLOCATION;
    
    if (pk && sk && sig) {
        rc = pq_sig_keypair(algorithm, pk, sk);
        if (rc == PQ_SUCCESS)
            rc = pq_sig_sign(algorithm, sig, &sig_len, msg, sizeof(msg) - 1, sk);
        if (rc == PQ_SUCCESS)
            rc = pq_sig_verify(algorithm, msg, sizeof(msg) - 1, sig, sig_len, pk);
        if (rc == PQ_SUCCESS) {
            sig[sig_len / 2] ^= 0x01;
            if (pq_sig_verify(algorithm, msg, sizeof(msg) - 1, sig, sig_len, pk) == PQ_SUCCESS)
                rc = PQ_ERR_CRYPTO_FAILED;  /* tampered signature accepted */
        }
    }
    
    if (sk) OPENSSL_cleanse(sk, sk_size);
    free(sk);
    free(pk);
    free(sig);
    return rc;
}
