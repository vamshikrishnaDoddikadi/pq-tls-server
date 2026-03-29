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
#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

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

static int pq_sig_keypair_mldsa(int algorithm, uint8_t *pk, uint8_t *sk) {
    const char *alg_name = pq_sig_algorithm_name(algorithm);
    if (!alg_name) return PQ_ERR_INVALID_ALGORITHM;
    
    OQS_SIG *sig = OQS_SIG_new(alg_name);
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

static int pq_sig_sign_mldsa(int algorithm, uint8_t *sig, size_t *sig_len,
                             const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    const char *alg_name = pq_sig_algorithm_name(algorithm);
    if (!alg_name) return PQ_ERR_INVALID_ALGORITHM;
    
    OQS_SIG *oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) return PQ_ERR_CRYPTO_FAILED;
    
    size_t max_sig_len = oqs_sig->length_signature;
    OQS_STATUS status = OQS_SIG_sign(oqs_sig, sig, sig_len, msg, msg_len, sk);
    OQS_SIG_free(oqs_sig);

    /* Check result and clear signature buffer on error.
     * Use max_sig_len rather than *sig_len which may be 0 or
     * undefined after a failed sign operation. */
    if (status != OQS_SUCCESS) {
        if (sig) {
            OPENSSL_cleanse(sig, max_sig_len);
        }
        if (sig_len) *sig_len = 0;
        return PQ_ERR_SIGNATURE_FAILED;
    }
    
    return PQ_SUCCESS;
}

static int pq_sig_verify_mldsa(int algorithm, const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    const char *alg_name = pq_sig_algorithm_name(algorithm);
    if (!alg_name) return PQ_ERR_INVALID_ALGORITHM;
    
    OQS_SIG *oqs_sig = OQS_SIG_new(alg_name);
    if (!oqs_sig) return PQ_ERR_CRYPTO_FAILED;
    
    OQS_STATUS status = OQS_SIG_verify(oqs_sig, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(oqs_sig);
    
    return (status == OQS_SUCCESS) ? PQ_SUCCESS : PQ_ERR_VERIFICATION_FAILED;
}

/* ========================================================================
 * Ed25519 (OpenSSL) Implementation
 * ======================================================================== */

static int pq_sig_keypair_ed25519(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) return PQ_ERR_CRYPTO_FAILED;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Extract raw keys (32 bytes each for Ed25519) */
    size_t pk_len = 32, sk_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0) {
        OPENSSL_cleanse(sk, 32);  /* Clear any partial key data */
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return PQ_SUCCESS;
}

static int pq_sig_sign_ed25519(uint8_t *sig, size_t *sig_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sk) {
    /* Create EVP_PKEY from raw private key */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;
    
    /* Create signing context */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Initialize signing (Ed25519 uses NULL for digest) */
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Sign message */
    if (EVP_DigestSign(md_ctx, sig, sig_len, msg, msg_len) <= 0) {
        if (sig && sig_len) {
            OPENSSL_cleanse(sig, *sig_len);  /* Clear any partial signature */
        }
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_SIGNATURE_FAILED;
    }
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return PQ_SUCCESS;
}

static int pq_sig_verify_ed25519(const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len,
                                 const uint8_t *pk) {
    /* Create EVP_PKEY from raw public key */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;
    
    /* Create verification context */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Initialize verification (Ed25519 uses NULL for digest) */
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Verify signature */
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    return (result == 1) ? PQ_SUCCESS : PQ_ERR_VERIFICATION_FAILED;
}

/* ========================================================================
 * ECDSA P-256 (OpenSSL) Implementation
 * ======================================================================== */

static int pq_sig_keypair_ecdsa_p256(uint8_t *pk, uint8_t *sk) {
    /* Create EC key generation context */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return PQ_ERR_CRYPTO_FAILED;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Set curve to P-256 */
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Generate key pair */
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Extract public key (uncompressed format: 0x04 || X || Y = 65 bytes) */
    size_t pk_len = 65;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0) {
        /* Fallback: use EC_POINT encoding */
        EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (!ec_key) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return PQ_ERR_CRYPTO_FAILED;
        }
        
        const EC_GROUP *group = EC_KEY_get0_group(ec_key);
        const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
        pk_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                     pk, 65, NULL);
        EC_KEY_free(ec_key);
        
        if (pk_len != 65) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return PQ_ERR_CRYPTO_FAILED;
        }
    }
    
    /* Extract private key (32 bytes) */
    size_t sk_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0) {
        /* Fallback: use EC_KEY encoding */
        EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (!ec_key) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return PQ_ERR_CRYPTO_FAILED;
        }
        
        const BIGNUM *priv_bn = EC_KEY_get0_private_key(ec_key);
        if (!priv_bn || BN_bn2binpad(priv_bn, sk, 32) != 32) {
            EC_KEY_free(ec_key);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return PQ_ERR_CRYPTO_FAILED;
        }
        EC_KEY_free(ec_key);
    }
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return PQ_SUCCESS;
}

static int pq_sig_sign_ecdsa_p256(uint8_t *sig, size_t *sig_len,
                                  const uint8_t *msg, size_t msg_len,
                                  const uint8_t *sk) {
    /* Create EC key from private key bytes */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) return PQ_ERR_CRYPTO_FAILED;
    
    BIGNUM *priv_bn = BN_bin2bn(sk, 32, NULL);
    if (!priv_bn || !EC_KEY_set_private_key(ec_key, priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        return PQ_ERR_CRYPTO_FAILED;
    }

    /* Derive public key from private key (must happen before freeing priv_bn) */
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point || !EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return PQ_ERR_CRYPTO_FAILED;
    }
    BN_free(priv_bn);
    EC_KEY_set_public_key(ec_key, pub_point);
    EC_POINT_free(pub_point);
    
    /* Create EVP_PKEY from EC_KEY */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        return PQ_ERR_CRYPTO_FAILED;
    }
    /* ec_key is now owned by pkey, don't free separately */
    
    /* Create signing context with SHA-256 */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Sign message */
    if (EVP_DigestSign(md_ctx, sig, sig_len, msg, msg_len) <= 0) {
        if (sig && sig_len) {
            OPENSSL_cleanse(sig, *sig_len);  /* Clear any partial signature */
        }
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_SIGNATURE_FAILED;
    }
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return PQ_SUCCESS;
}

static int pq_sig_verify_ecdsa_p256(const uint8_t *msg, size_t msg_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const uint8_t *pk) {
    /* Create EC key from public key bytes (uncompressed format) */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) return PQ_ERR_CRYPTO_FAILED;
    
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point || !EC_POINT_oct2point(group, pub_point, pk, 65, NULL)) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return PQ_ERR_CRYPTO_FAILED;
    }
    EC_POINT_free(pub_point);
    
    /* Create EVP_PKEY from EC_KEY */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        return PQ_ERR_CRYPTO_FAILED;
    }
    /* ec_key is now owned by pkey */
    
    /* Create verification context with SHA-256 */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Verify signature */
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    return (result == 1) ? PQ_SUCCESS : PQ_ERR_VERIFICATION_FAILED;
}

/* ========================================================================
 * RSA-2048 (OpenSSL) Implementation
 * ======================================================================== */

static int pq_sig_keypair_rsa2048(uint8_t *pk, uint8_t *sk) {
    /* Create RSA key generation context */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return PQ_ERR_CRYPTO_FAILED;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Set key size to 2048 bits */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Generate key pair */
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Serialize keys to DER format */
    unsigned char *pk_der = NULL, *sk_der = NULL;
    int pk_len = i2d_PUBKEY(pkey, &pk_der);
    int sk_len = i2d_PrivateKey(pkey, &sk_der);
    
    if (pk_len <= 0 || sk_len <= 0 || 
        pk_len > (int)PQ_SIG_RSA2048_PUBLICKEY_BYTES ||
        sk_len > (int)PQ_SIG_RSA2048_SECRETKEY_BYTES) {
        OPENSSL_free(pk_der);
        OPENSSL_free(sk_der);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Copy to output buffers */
    memcpy(pk, pk_der, pk_len);
    memcpy(sk, sk_der, sk_len);
    
    /* Zero remaining space */
    if (pk_len < (int)PQ_SIG_RSA2048_PUBLICKEY_BYTES) {
        memset(pk + pk_len, 0, PQ_SIG_RSA2048_PUBLICKEY_BYTES - pk_len);
    }
    if (sk_len < (int)PQ_SIG_RSA2048_SECRETKEY_BYTES) {
        memset(sk + sk_len, 0, PQ_SIG_RSA2048_SECRETKEY_BYTES - sk_len);
    }
    
    OPENSSL_free(pk_der);
    OPENSSL_free(sk_der);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return PQ_SUCCESS;
}

static int pq_sig_sign_rsa2048(uint8_t *sig, size_t *sig_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sk) {
    /* Parse private key from DER format */
    const unsigned char *sk_ptr = sk;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &sk_ptr, PQ_SIG_RSA2048_SECRETKEY_BYTES);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;
    
    /* Create signing context with SHA-256 */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Sign message */
    if (EVP_DigestSign(md_ctx, sig, sig_len, msg, msg_len) <= 0) {
        if (sig && sig_len) {
            OPENSSL_cleanse(sig, *sig_len);  /* Clear any partial signature */
        }
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_SIGNATURE_FAILED;
    }
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return PQ_SUCCESS;
}

static int pq_sig_verify_rsa2048(const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len,
                                 const uint8_t *pk) {
    /* Parse public key from DER format */
    const unsigned char *pk_ptr = pk;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &pk_ptr, PQ_SIG_RSA2048_PUBLICKEY_BYTES);
    if (!pkey) return PQ_ERR_CRYPTO_FAILED;
    
    /* Create verification context with SHA-256 */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Verify signature */
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    return (result == 1) ? PQ_SUCCESS : PQ_ERR_VERIFICATION_FAILED;
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
    
    /* Dispatch to appropriate implementation */
    switch (algorithm) {
        /* ML-DSA (Post-Quantum) */
        case PQ_SIG_MLDSA44:
        case PQ_SIG_MLDSA65:
        case PQ_SIG_MLDSA87:
            return pq_sig_sign_mldsa(algorithm, sig, sig_len, msg, msg_len, sk);
        
        /* Classical Fallbacks */
        case PQ_SIG_ED25519:
            return pq_sig_sign_ed25519(sig, sig_len, msg, msg_len, sk);
        case PQ_SIG_ECDSA_P256:
            return pq_sig_sign_ecdsa_p256(sig, sig_len, msg, msg_len, sk);
        case PQ_SIG_RSA2048:
            return pq_sig_sign_rsa2048(sig, sig_len, msg, msg_len, sk);
        
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
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
