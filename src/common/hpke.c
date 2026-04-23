/**
 * @file hpke.c
 * @brief RFC 9180 Hybrid Public Key Encryption implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements RFC 9180 HPKE (Hybrid Public Key Encryption) with
 * support for post-quantum key encapsulation (ML-KEM) and hybrid modes
 * combining classical (X25519) with post-quantum algorithms.
 */

#include "hpke.h"
#include "pq_errors.h"
#include "pq_utils_extra.h"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 * HPKE Size Query Functions
 * ======================================================================== */

/**
 * @brief Get public key size for KEM algorithm
 */
size_t pq_hpke_publickey_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:
            return HPKE_X25519_PUBLICKEY_BYTES;
        case HPKE_KEM_MLKEM768:
            return HPKE_MLKEM768_PUBLICKEY_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT:
            return HPKE_HYBRID_PUBLICKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get secret key size for KEM algorithm
 */
size_t pq_hpke_secretkey_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:
            return HPKE_X25519_SECRETKEY_BYTES;
        case HPKE_KEM_MLKEM768:
            return HPKE_MLKEM768_SECRETKEY_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT:
            return HPKE_HYBRID_SECRETKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get encapsulated key size for KEM algorithm
 */
size_t pq_hpke_encapsulated_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:
            return HPKE_X25519_ENCAPSULATED_BYTES;
        case HPKE_KEM_MLKEM768:
            return HPKE_MLKEM768_ENCAPSULATED_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT:
            return HPKE_HYBRID_ENCAPSULATED_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get shared secret size for KEM algorithm
 */
size_t pq_hpke_sharedsecret_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:
            return HPKE_X25519_SHAREDSECRET_BYTES;
        case HPKE_KEM_MLKEM768:
            return HPKE_MLKEM768_SHAREDSECRET_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT:
            return HPKE_HYBRID_SHAREDSECRET_BYTES;
        default:
            return 0;
    }
}

/* ========================================================================
 * HPKE Context Management
 * ======================================================================== */

/**
 * @brief Initialize HPKE context
 */
pq_hpke_t* pq_hpke_init(int kem, int aead) {
    /* Validate algorithms */
    if (pq_hpke_publickey_bytes(kem) == 0) {
        return NULL;
    }
    if (aead != HPKE_AEAD_AES256GCM && aead != HPKE_AEAD_CHACHAPOLY) {
        return NULL;
    }
    
    /* Allocate context */
    pq_hpke_t *hpke = calloc(1, sizeof(pq_hpke_t));
    if (!hpke) {
        return NULL;
    }
    
    hpke->kem = kem;
    hpke->aead = aead;
    hpke->secret_key = NULL;
    hpke->secret_key_len = 0;
    
    return hpke;
}

/**
 * @brief Free HPKE context
 */
void pq_hpke_free(pq_hpke_t *hpke) {
    if (!hpke) {
        return;
    }
    
    /* Securely clear secret key material */
    if (hpke->secret_key) {
        OPENSSL_cleanse(hpke->secret_key, hpke->secret_key_len);
        free(hpke->secret_key);
    }
    
    /* Clear context structure */
    OPENSSL_cleanse(hpke, sizeof(pq_hpke_t));
    free(hpke);
}

/* ========================================================================
 * X25519 KEM Operations (OpenSSL)
 * ======================================================================== */

/**
 * @brief Generate X25519 key pair
 */
static int x25519_keygen(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t pk_len = HPKE_X25519_PUBLICKEY_BYTES;
    size_t sk_len = HPKE_X25519_SECRETKEY_BYTES;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Create key generation context */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) {
        goto cleanup;
    }
    
    /* Generate key pair */
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        goto cleanup;
    }
    
    /* Extract public key */
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0) {
        goto cleanup;
    }
    if (pk_len != HPKE_X25519_PUBLICKEY_BYTES) {
        goto cleanup;
    }
    
    /* Extract secret key */
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0) {
        goto cleanup;
    }
    if (sk_len != HPKE_X25519_SECRETKEY_BYTES) {
        goto cleanup;
    }
    
    ret = PQ_SUCCESS;
    
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

/**
 * @brief X25519 encapsulation (generate ephemeral key and derive shared secret)
 */
static int x25519_encapsulate(uint8_t *enc, uint8_t *ss, const uint8_t *pk) {
    EVP_PKEY *ephemeral_key = NULL;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t enc_len = HPKE_X25519_PUBLICKEY_BYTES;
    size_t ss_len = HPKE_X25519_SHAREDSECRET_BYTES;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Generate ephemeral key pair */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen(ctx, &ephemeral_key) <= 0) {
        goto cleanup;
    }
    
    /* Extract ephemeral public key (this is the encapsulated key) */
    if (EVP_PKEY_get_raw_public_key(ephemeral_key, enc, &enc_len) <= 0) {
        goto cleanup;
    }
    if (enc_len != HPKE_X25519_ENCAPSULATED_BYTES) {
        goto cleanup;
    }
    
    /* Load peer's public key */
    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk, HPKE_X25519_PUBLICKEY_BYTES);
    if (!peer_key) {
        goto cleanup;
    }
    
    /* Derive shared secret */
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new(ephemeral_key, NULL);
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, ss, &ss_len) <= 0) {
        goto cleanup;
    }
    if (ss_len != HPKE_X25519_SHAREDSECRET_BYTES) {
        goto cleanup;
    }
    
    ret = PQ_SUCCESS;
    
cleanup:
    if (ephemeral_key) EVP_PKEY_free(ephemeral_key);
    if (peer_key) EVP_PKEY_free(peer_key);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

/**
 * @brief X25519 decapsulation (derive shared secret from encapsulated key)
 */
static int x25519_decapsulate(uint8_t *ss, const uint8_t *enc, const uint8_t *sk) {
    EVP_PKEY *my_key = NULL;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t ss_len = HPKE_X25519_SHAREDSECRET_BYTES;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Load our secret key */
    my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, HPKE_X25519_SECRETKEY_BYTES);
    if (!my_key) {
        goto cleanup;
    }
    
    /* Load peer's ephemeral public key (the encapsulated key) */
    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, enc, HPKE_X25519_ENCAPSULATED_BYTES);
    if (!peer_key) {
        goto cleanup;
    }
    
    /* Derive shared secret */
    ctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, ss, &ss_len) <= 0) {
        goto cleanup;
    }
    if (ss_len != HPKE_X25519_SHAREDSECRET_BYTES) {
        goto cleanup;
    }
    
    ret = PQ_SUCCESS;
    
cleanup:
    if (my_key) EVP_PKEY_free(my_key);
    if (peer_key) EVP_PKEY_free(peer_key);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* ========================================================================
 * ML-KEM-768 KEM Operations (liboqs)
 * ======================================================================== */

/**
 * @brief Generate ML-KEM-768 key pair
 */
static int mlkem768_keygen(uint8_t *pk, uint8_t *sk) {
    OQS_KEM *kem = NULL;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Initialize ML-KEM-768 */
    kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) {
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Verify sizes match our constants */
    if (kem->length_public_key != HPKE_MLKEM768_PUBLICKEY_BYTES ||
        kem->length_secret_key != HPKE_MLKEM768_SECRETKEY_BYTES) {
        OQS_KEM_free(kem);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Generate key pair */
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    ret = PQ_SUCCESS;
    OQS_KEM_free(kem);
    return ret;
}

/**
 * @brief ML-KEM-768 encapsulation
 */
static int mlkem768_encapsulate(uint8_t *enc, uint8_t *ss, const uint8_t *pk) {
    OQS_KEM *kem = NULL;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Initialize ML-KEM-768 */
    kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) {
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Verify sizes */
    if (kem->length_ciphertext != HPKE_MLKEM768_ENCAPSULATED_BYTES ||
        kem->length_shared_secret != HPKE_MLKEM768_SHAREDSECRET_BYTES) {
        OQS_KEM_free(kem);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Encapsulate */
    if (OQS_KEM_encaps(kem, enc, ss, pk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    ret = PQ_SUCCESS;
    OQS_KEM_free(kem);
    return ret;
}

/**
 * @brief ML-KEM-768 decapsulation
 */
static int mlkem768_decapsulate(uint8_t *ss, const uint8_t *enc, const uint8_t *sk) {
    OQS_KEM *kem = NULL;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Initialize ML-KEM-768 */
    kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) {
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Verify sizes */
    if (kem->length_shared_secret != HPKE_MLKEM768_SHAREDSECRET_BYTES) {
        OQS_KEM_free(kem);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Decapsulate */
    if (OQS_KEM_decaps(kem, ss, enc, sk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    ret = PQ_SUCCESS;
    OQS_KEM_free(kem);
    return ret;
}

/* ========================================================================
 * HPKE Key Operations (Public API)
 * ======================================================================== */

/**
 * @brief Generate HPKE key pair
 */
int pq_hpke_keygen(pq_hpke_t *hpke, uint8_t *pk, size_t pk_len,
                   uint8_t *sk, size_t sk_len) {
    if (!hpke || !pk || !sk) {
        return PQ_ERR_NULL_POINTER;
    }
    
    size_t expected_pk_len = pq_hpke_publickey_bytes(hpke->kem);
    size_t expected_sk_len = pq_hpke_secretkey_bytes(hpke->kem);
    
    if (pk_len < expected_pk_len || sk_len < expected_sk_len) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    int ret;
    
    switch (hpke->kem) {
        case HPKE_KEM_X25519:
            ret = x25519_keygen(pk, sk);
            break;
            
        case HPKE_KEM_MLKEM768:
            ret = mlkem768_keygen(pk, sk);
            break;
            
        case HPKE_KEM_X25519_MLKEM768_CONCAT: {
            /* Generate X25519 key pair (first part) */
            ret = x25519_keygen(pk, sk);
            if (ret != PQ_SUCCESS) {
                /* Cleanse X25519 keys on failure before returning */
                OPENSSL_cleanse(pk, HPKE_X25519_PUBLICKEY_BYTES);
                OPENSSL_cleanse(sk, HPKE_X25519_SECRETKEY_BYTES);
                return ret;
            }

            /* Generate ML-KEM-768 key pair (second part) */
            ret = mlkem768_keygen(
                pk + HPKE_X25519_PUBLICKEY_BYTES,
                sk + HPKE_X25519_SECRETKEY_BYTES
            );
            if (ret != PQ_SUCCESS) {
                /* SECURITY: Cleanse BOTH X25519 and ML-KEM portions on failure */
                OPENSSL_cleanse(pk, HPKE_X25519_PUBLICKEY_BYTES);
                OPENSSL_cleanse(sk, HPKE_X25519_SECRETKEY_BYTES);
                OPENSSL_cleanse(pk + HPKE_X25519_PUBLICKEY_BYTES, HPKE_MLKEM768_PUBLICKEY_BYTES);
                OPENSSL_cleanse(sk + HPKE_X25519_SECRETKEY_BYTES, HPKE_MLKEM768_SECRETKEY_BYTES);
                return ret;
            }
            break;
        }
            
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
    
    return ret;
}

/**
 * @brief Encapsulate shared secret (sender side)
 */
int pq_hpke_encapsulate(pq_hpke_t *hpke, uint8_t *enc, size_t *enc_len,
                        uint8_t *ss, size_t ss_len,
                        const uint8_t *pk, size_t pk_len) {
    if (!hpke || !enc || !enc_len || !ss || !pk) {
        return PQ_ERR_NULL_POINTER;
    }
    
    size_t expected_pk_len = pq_hpke_publickey_bytes(hpke->kem);
    size_t expected_ss_len = pq_hpke_sharedsecret_bytes(hpke->kem);
    
    if (pk_len < expected_pk_len || ss_len < expected_ss_len) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    int ret;
    
    switch (hpke->kem) {
        case HPKE_KEM_X25519:
            ret = x25519_encapsulate(enc, ss, pk);
            if (ret == PQ_SUCCESS) {
                *enc_len = HPKE_X25519_ENCAPSULATED_BYTES;
            }
            break;
            
        case HPKE_KEM_MLKEM768:
            ret = mlkem768_encapsulate(enc, ss, pk);
            if (ret == PQ_SUCCESS) {
                *enc_len = HPKE_MLKEM768_ENCAPSULATED_BYTES;
            }
            break;
            
        case HPKE_KEM_X25519_MLKEM768_CONCAT: {
            /* Encapsulate with X25519 (first part) */
            uint8_t x25519_enc[HPKE_X25519_ENCAPSULATED_BYTES];
            uint8_t x25519_ss[HPKE_X25519_SHAREDSECRET_BYTES];
            
            ret = x25519_encapsulate(x25519_enc, x25519_ss, pk);
            if (ret != PQ_SUCCESS) {
                OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
                return ret;
            }
            
            /* Encapsulate with ML-KEM-768 (second part) */
            uint8_t mlkem_enc[HPKE_MLKEM768_ENCAPSULATED_BYTES];
            uint8_t mlkem_ss[HPKE_MLKEM768_SHAREDSECRET_BYTES];
            
            ret = mlkem768_encapsulate(
                mlkem_enc,
                mlkem_ss,
                pk + HPKE_X25519_PUBLICKEY_BYTES
            );
            if (ret != PQ_SUCCESS) {
                OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
                OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
                return ret;
            }
            
            /* Concatenate encapsulated keys */
            memcpy(enc, x25519_enc, HPKE_X25519_ENCAPSULATED_BYTES);
            memcpy(enc + HPKE_X25519_ENCAPSULATED_BYTES, mlkem_enc, HPKE_MLKEM768_ENCAPSULATED_BYTES);
            *enc_len = HPKE_HYBRID_ENCAPSULATED_BYTES;
            
            /* Concatenate shared secrets */
            memcpy(ss, x25519_ss, HPKE_X25519_SHAREDSECRET_BYTES);
            memcpy(ss + HPKE_X25519_SHAREDSECRET_BYTES, mlkem_ss, HPKE_MLKEM768_SHAREDSECRET_BYTES);
            
            /* Secure cleanup */
            OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
            OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
            break;
        }
            
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
    
    return ret;
}

/**
 * @brief Decapsulate shared secret (receiver side)
 */
int pq_hpke_decapsulate(pq_hpke_t *hpke, uint8_t *ss, size_t ss_len,
                        const uint8_t *enc, size_t enc_len,
                        const uint8_t *sk, size_t sk_len) {
    if (!hpke || !ss || !enc || !sk) {
        return PQ_ERR_NULL_POINTER;
    }
    
    size_t expected_enc_len = pq_hpke_encapsulated_bytes(hpke->kem);
    size_t expected_ss_len = pq_hpke_sharedsecret_bytes(hpke->kem);
    size_t expected_sk_len = pq_hpke_secretkey_bytes(hpke->kem);
    
    if (enc_len < expected_enc_len || ss_len < expected_ss_len || sk_len < expected_sk_len) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    int ret;
    
    switch (hpke->kem) {
        case HPKE_KEM_X25519:
            ret = x25519_decapsulate(ss, enc, sk);
            break;
            
        case HPKE_KEM_MLKEM768:
            ret = mlkem768_decapsulate(ss, enc, sk);
            break;
            
        case HPKE_KEM_X25519_MLKEM768_CONCAT: {
            /* Decapsulate X25519 (first part) */
            uint8_t x25519_ss[HPKE_X25519_SHAREDSECRET_BYTES];
            
            ret = x25519_decapsulate(x25519_ss, enc, sk);
            if (ret != PQ_SUCCESS) {
                OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
                return ret;
            }
            
            /* Decapsulate ML-KEM-768 (second part) */
            uint8_t mlkem_ss[HPKE_MLKEM768_SHAREDSECRET_BYTES];
            
            ret = mlkem768_decapsulate(
                mlkem_ss,
                enc + HPKE_X25519_ENCAPSULATED_BYTES,
                sk + HPKE_X25519_SECRETKEY_BYTES
            );
            if (ret != PQ_SUCCESS) {
                OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
                OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
                return ret;
            }
            
            /* Concatenate shared secrets */
            memcpy(ss, x25519_ss, HPKE_X25519_SHAREDSECRET_BYTES);
            memcpy(ss + HPKE_X25519_SHAREDSECRET_BYTES, mlkem_ss, HPKE_MLKEM768_SHAREDSECRET_BYTES);
            
            /* Secure cleanup */
            OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
            OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
            break;
        }
            
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
    
    return ret;
}

/* ========================================================================
 * HPKE AEAD Operations (Public API)
 * ======================================================================== */

/**
 * @brief Seal (encrypt and authenticate) plaintext
 */
int pq_hpke_seal(pq_hpke_t *hpke, uint8_t *ct, size_t *ct_len,
                 const uint8_t *pt, size_t pt_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ss, size_t ss_len) {
    if (!hpke || !ct || !ct_len || !pt || !ss) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Validate shared secret size (need at least 32 bytes for key) */
    if (ss_len < 32) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Select cipher based on AEAD algorithm */
    const EVP_CIPHER *cipher;
    switch (hpke->aead) {
        case HPKE_AEAD_AES256GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case HPKE_AEAD_CHACHAPOLY:
            cipher = EVP_chacha20_poly1305();
            break;
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Derive key from shared secret (use first 32 bytes) */
    uint8_t key[32];
    memcpy(key, ss, 32);
    
    /* Generate random IV (12 bytes for GCM/ChaCha20) */
    uint8_t iv[HPKE_AEAD_IV_BYTES];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        OPENSSL_cleanse(key, sizeof(key));
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    /* Initialize cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    int ret = PQ_ERR_CRYPTO_FAILED;
    int len, len2;
    
    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }
    
    /* Process AAD if provided */
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            goto cleanup;
        }
    }
    
    /* Encrypt plaintext (output starts after IV) */
    if (EVP_EncryptUpdate(ctx, ct + HPKE_AEAD_IV_BYTES, &len, pt, pt_len) != 1) {
        goto cleanup;
    }
    
    /* Finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, ct + HPKE_AEAD_IV_BYTES + len, &len2) != 1) {
        goto cleanup;
    }
    
    /* Get authentication tag (16 bytes, append after ciphertext) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, HPKE_AEAD_TAG_BYTES,
                            ct + HPKE_AEAD_IV_BYTES + len + len2) != 1) {
        goto cleanup;
    }
    
    /* Prepend IV to ciphertext */
    memcpy(ct, iv, HPKE_AEAD_IV_BYTES);
    
    /* Total ciphertext length: IV + encrypted_data + tag */
    *ct_len = HPKE_AEAD_IV_BYTES + len + len2 + HPKE_AEAD_TAG_BYTES;
    
    ret = PQ_SUCCESS;
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return ret;
}

/**
 * @brief Open (decrypt and verify) ciphertext
 */
int pq_hpke_open(pq_hpke_t *hpke, uint8_t *pt, size_t *pt_len,
                 const uint8_t *ct, size_t ct_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ss, size_t ss_len) {
    if (!hpke || !pt || !pt_len || !ct || !ss) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Validate shared secret size */
    if (ss_len < 32) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Validate ciphertext size (must have at least IV + tag) */
    if (ct_len < HPKE_AEAD_IV_BYTES + HPKE_AEAD_TAG_BYTES) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Select cipher based on AEAD algorithm */
    const EVP_CIPHER *cipher;
    switch (hpke->aead) {
        case HPKE_AEAD_AES256GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case HPKE_AEAD_CHACHAPOLY:
            cipher = EVP_chacha20_poly1305();
            break;
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Derive key from shared secret (use first 32 bytes) */
    uint8_t key[32];
    memcpy(key, ss, 32);
    
    /* Extract IV from first 12 bytes of ciphertext */
    uint8_t iv[HPKE_AEAD_IV_BYTES];
    memcpy(iv, ct, HPKE_AEAD_IV_BYTES);
    
    /* Calculate encrypted data length (total - IV - tag) */
    size_t encrypted_len = ct_len - HPKE_AEAD_IV_BYTES - HPKE_AEAD_TAG_BYTES;
    
    /* Extract tag from end of ciphertext */
    uint8_t tag[HPKE_AEAD_TAG_BYTES];
    memcpy(tag, ct + ct_len - HPKE_AEAD_TAG_BYTES, HPKE_AEAD_TAG_BYTES);
    
    /* Initialize cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        return PQ_ERR_CRYPTO_FAILED;
    }
    
    int ret = PQ_ERR_CRYPTO_FAILED;
    int len, len2;
    
    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto cleanup;
    }
    
    /* Process AAD if provided */
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            goto cleanup;
        }
    }
    
    /* Decrypt ciphertext (skip IV at beginning) */
    if (EVP_DecryptUpdate(ctx, pt, &len, ct + HPKE_AEAD_IV_BYTES, encrypted_len) != 1) {
        goto cleanup;
    }
    
    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, HPKE_AEAD_TAG_BYTES, tag) != 1) {
        goto cleanup;
    }
    
    /* Finalize decryption (verifies tag) */
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len2) != 1) {
        /* Tag verification failed */
        ret = PQ_ERR_VERIFICATION_FAILED;
        goto cleanup;
    }
    
    /* Set plaintext length */
    *pt_len = len + len2;
    
    ret = PQ_SUCCESS;
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(tag, sizeof(tag));
    return ret;
}
