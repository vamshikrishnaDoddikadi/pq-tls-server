/**
 * @file hybrid_kex.c
 * @brief Hybrid Key Exchange implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements hybrid key exchange combining classical ECDH
 * algorithms (X25519, ECDH P-256) with post-quantum ML-KEM algorithms.
 */

#include "hybrid_kex.h"
#include "hybrid_combiner.h"
#include "kem_classical.h"
#include "pq_kem.h"
#include "pq_errors.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 * Classical Algorithm Size Constants
 * ======================================================================== */

/* X25519 sizes */
#define X25519_PUBLICKEY_BYTES  32
#define X25519_SECRETKEY_BYTES  32
#define X25519_SHAREDSECRET_BYTES 32

/* ECDH P-256 sizes */
#define P256_PUBLICKEY_BYTES    PQ_P256_PUBLICKEY_BYTES   /* 0x04 || x || y */
#define P256_SECRETKEY_BYTES    PQ_P256_SECRETKEY_BYTES
#define P256_SHAREDSECRET_BYTES PQ_P256_SHAREDSECRET_BYTES

/* Largest classical sizes (used for stack buffers) */
#define CLASSICAL_MAX_PK  P256_PUBLICKEY_BYTES
#define CLASSICAL_MAX_SK  P256_SECRETKEY_BYTES
#define CLASSICAL_MAX_SS  P256_SHAREDSECRET_BYTES

/* Output size of both combination modes */
#define HYBRID_SS_BYTES   32
#define PQ_SS_BYTES       32

/* ========================================================================
 * Helper Functions - Classical Algorithm Sizes
 * ======================================================================== */

/**
 * @brief Get public key size for classical algorithm
 */
static size_t get_classical_pk_size(int classical_alg) {
    switch (classical_alg) {
        case HYBRID_CLASSICAL_X25519:
            return X25519_PUBLICKEY_BYTES;
        case HYBRID_CLASSICAL_P256:
            return P256_PUBLICKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get secret key size for classical algorithm
 */
static size_t get_classical_sk_size(int classical_alg) {
    switch (classical_alg) {
        case HYBRID_CLASSICAL_X25519:
            return X25519_SECRETKEY_BYTES;
        case HYBRID_CLASSICAL_P256:
            return P256_SECRETKEY_BYTES;
        default:
            return 0;
    }
}

/**
 * @brief Get shared secret size for classical algorithm
 */
static size_t get_classical_ss_size(int classical_alg) {
    switch (classical_alg) {
        case HYBRID_CLASSICAL_X25519:
            return X25519_SHAREDSECRET_BYTES;
        case HYBRID_CLASSICAL_P256:
            return P256_SHAREDSECRET_BYTES;
        default:
            return 0;
    }
}

/* ========================================================================
 * X25519 Operations
 * ======================================================================== */

/**
 * @brief Generate X25519 key pair (sk wiped on failure)
 */
static int x25519_keypair(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t pk_len = X25519_PUBLICKEY_BYTES;
    size_t sk_len = X25519_SECRETKEY_BYTES;
    int ret = PQ_ERR_KEY_GENERATION_FAILED;

    if (!ctx) goto cleanup;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0 ||
        pk_len != X25519_PUBLICKEY_BYTES) goto cleanup;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0 ||
        sk_len != X25519_SECRETKEY_BYTES) goto cleanup;
    ret = PQ_SUCCESS;

cleanup:
    if (ret != PQ_SUCCESS) OPENSSL_cleanse(sk, X25519_SECRETKEY_BYTES);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/**
 * @brief Recompute the X25519 public key from a secret key
 */
static int x25519_public_from_private(const uint8_t *sk, uint8_t *pk) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk,
                                                  X25519_SECRETKEY_BYTES);
    size_t pk_len = X25519_PUBLICKEY_BYTES;
    int ret = PQ_ERR_CRYPTO_FAILED;

    if (pkey && EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) == 1 &&
        pk_len == X25519_PUBLICKEY_BYTES)
        ret = PQ_SUCCESS;
    EVP_PKEY_free(pkey);
    return ret;
}

/**
 * @brief Derive X25519 shared secret
 *
 * SECURITY: OpenSSL's X25519 derive fails when the result is all-zero, i.e.
 * for the identity / low-order peer points; the explicit check below makes
 * that rejection independent of the OpenSSL version.  CWE-295
 */
static int x25519_derive(uint8_t *ss, const uint8_t *sk, const uint8_t *peer_pk) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk,
                                                  X25519_SECRETKEY_BYTES);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk,
                                                 X25519_PUBLICKEY_BYTES);
    EVP_PKEY_CTX *ctx = NULL;
    size_t ss_len = X25519_SHAREDSECRET_BYTES;
    int ret = PQ_ERR_CRYPTO_FAILED;

    if (!pkey || !peer) goto cleanup;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto cleanup;
    if (EVP_PKEY_derive(ctx, ss, &ss_len) <= 0 ||
        ss_len != X25519_SHAREDSECRET_BYTES) goto cleanup;

    uint8_t acc = 0;
    for (size_t i = 0; i < X25519_SHAREDSECRET_BYTES; i++) acc |= ss[i];
    if (acc == 0) goto cleanup;

    ret = PQ_SUCCESS;

cleanup:
    if (ret != PQ_SUCCESS) OPENSSL_cleanse(ss, X25519_SHAREDSECRET_BYTES);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(pkey);
    return ret;
}

/* ========================================================================
 * Classical dispatch (ECDH P-256 via kem_classical.c raw-key helpers,
 * which use EVP_PKEY_fromdata / OSSL_PARAM and validate peer points)
 * ======================================================================== */

static int classical_keypair(int alg, uint8_t *pk, uint8_t *sk) {
    switch (alg) {
        case HYBRID_CLASSICAL_X25519: return x25519_keypair(pk, sk);
        case HYBRID_CLASSICAL_P256:   return pq_p256_generate_raw(pk, sk);
        default:                      return PQ_ERR_INVALID_PARAMETER;
    }
}

static int classical_derive(int alg, uint8_t *ss, const uint8_t *sk, const uint8_t *peer_pk) {
    switch (alg) {
        case HYBRID_CLASSICAL_X25519: return x25519_derive(ss, sk, peer_pk);
        case HYBRID_CLASSICAL_P256:   return pq_p256_ecdh_raw(sk, peer_pk, ss);
        default:                      return PQ_ERR_INVALID_PARAMETER;
    }
}

static int classical_public_from_private(int alg, const uint8_t *sk, uint8_t *pk) {
    switch (alg) {
        case HYBRID_CLASSICAL_X25519: return x25519_public_from_private(sk, pk);
        case HYBRID_CLASSICAL_P256:   return pq_p256_public_from_private(sk, pk);
        default:                      return PQ_ERR_INVALID_PARAMETER;
    }
}

/* ========================================================================
 * Shared secret combination
 * ======================================================================== */

/**
 * @brief Combine the component secrets according to the hybrid mode
 *
 * CONCAT: ss = SHA3-256(pq_ss || classical_ss || classical_ct || classical_pk || label)
 *         label = "pq-tls/hybrid-kex/v2" || I2OSP(classical_alg,1) || I2OSP(pq_alg,1)
 *         Every hashed field has a fixed length for a given (classical, pq)
 *         pair and every label has the same length with a unique 2-byte
 *         suffix, so the encoding is injective across all supported suites.
 * XOR:    deprecated, insecure; see hybrid_kex.h.
 */
static int combine_secrets(const pq_hybrid_kex_t *kex,
                           const uint8_t *classical_ss, size_t classical_ss_len,
                           const uint8_t *pq_ss,
                           const uint8_t *classical_ct, size_t classical_ct_len,
                           const uint8_t *classical_pk, size_t classical_pk_len,
                           uint8_t *ss) {
    if (kex->mode == HYBRID_MODE_CONCAT) {
        static const char prefix[] = "pq-tls/hybrid-kex/v2";
        uint8_t label[sizeof(prefix) - 1 + 2];
        memcpy(label, prefix, sizeof(prefix) - 1);
        label[sizeof(prefix) - 1] = (uint8_t)kex->classical_alg;
        label[sizeof(prefix)] = (uint8_t)kex->pq_alg;
        return pq_combiner_xwing_style(pq_ss, PQ_SS_BYTES,
                                       classical_ss, classical_ss_len,
                                       classical_ct, classical_ct_len,
                                       classical_pk, classical_pk_len,
                                       label, sizeof(label), ss);
    }
    if (kex->mode == HYBRID_MODE_XOR) {
        /* DEPRECATED / INSECURE: kept for configuration compatibility only */
        if (classical_ss_len != HYBRID_SS_BYTES) return PQ_ERR_INVALID_PARAMETER;
        for (size_t i = 0; i < HYBRID_SS_BYTES; i++)
            ss[i] = classical_ss[i] ^ pq_ss[i];
        return PQ_SUCCESS;
    }
    return PQ_ERR_INVALID_PARAMETER;
}


/* ========================================================================
 * Main Hybrid Key Exchange Functions
 * ======================================================================== */

pq_hybrid_kex_t* pq_hybrid_kex_init(int classical_alg, int pq_alg, int mode) {
    /* Validate parameters */
    if (classical_alg != HYBRID_CLASSICAL_X25519 && 
        classical_alg != HYBRID_CLASSICAL_P256) {
        return NULL;
    }
    
    if (pq_alg != PQ_KEM_MLKEM512 && 
        pq_alg != PQ_KEM_MLKEM768 && 
        pq_alg != PQ_KEM_MLKEM1024) {
        return NULL;
    }
    
    if (mode != HYBRID_MODE_CONCAT && mode != HYBRID_MODE_XOR) {
        return NULL;
    }
    
    /* Allocate context */
    pq_hybrid_kex_t *kex = (pq_hybrid_kex_t*)calloc(1, sizeof(pq_hybrid_kex_t));
    if (!kex) {
        return NULL;
    }
    
    kex->classical_alg = classical_alg;
    kex->pq_alg = pq_alg;
    kex->mode = mode;
    
    return kex;
}

void pq_hybrid_kex_free(pq_hybrid_kex_t *kex) {
    if (kex) {
        OPENSSL_cleanse(kex, sizeof(pq_hybrid_kex_t));
        free(kex);
    }
}

int pq_hybrid_kex_keypair(pq_hybrid_kex_t *kex, uint8_t *pk, size_t *pk_len,
                          uint8_t *sk, size_t *sk_len) {
    if (!kex || !pk || !pk_len || !sk || !sk_len) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    int ret;
    size_t classical_pk_len = get_classical_pk_size(kex->classical_alg);
    size_t classical_sk_len = get_classical_sk_size(kex->classical_alg);
    size_t pq_pk_len = pq_kem_publickey_bytes(kex->pq_alg);
    size_t pq_sk_len = pq_kem_secretkey_bytes(kex->pq_alg);
    if (classical_pk_len == 0 || pq_pk_len == 0) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Generate classical key pair (wipes its sk on failure) */
    ret = classical_keypair(kex->classical_alg, pk, sk);
    if (ret != PQ_SUCCESS) {
        return ret;
    }
    
    /* Generate PQ key pair */
    ret = pq_kem_keypair(kex->pq_alg, pk + classical_pk_len, sk + classical_sk_len);
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(sk, classical_sk_len + pq_sk_len);
        return ret;
    }
    
    /* Set output lengths */
    *pk_len = classical_pk_len + pq_pk_len;
    *sk_len = classical_sk_len + pq_sk_len;
    
    return PQ_SUCCESS;
}

int pq_hybrid_kex_encapsulate(pq_hybrid_kex_t *kex, uint8_t *ct, size_t *ct_len,
                              uint8_t *ss, size_t *ss_len,
                              const uint8_t *pk, size_t pk_len) {
    if (!kex || !ct || !ct_len || !ss || !ss_len || !pk) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    size_t classical_pk_len = get_classical_pk_size(kex->classical_alg);
    size_t classical_ss_len = get_classical_ss_size(kex->classical_alg);
    size_t pq_pk_len = pq_kem_publickey_bytes(kex->pq_alg);
    size_t pq_ct_len = pq_kem_ciphertext_bytes(kex->pq_alg);
    if (classical_pk_len == 0 || pq_pk_len == 0) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Validate input public key length (exact) */
    if (pk_len != classical_pk_len + pq_pk_len) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Split public key and ciphertext buffers */
    const uint8_t *classical_pk = pk;
    const uint8_t *pq_pk = pk + classical_pk_len;
    uint8_t *classical_ct = ct;                    /* ephemeral public key */
    uint8_t *pq_ct = ct + classical_pk_len;
    
    uint8_t classical_eph_sk[CLASSICAL_MAX_SK];
    uint8_t classical_ss[CLASSICAL_MAX_SS];
    uint8_t pq_ss[PQ_SS_BYTES];
    
    /* Classical encapsulation: ephemeral key pair + ECDH with recipient key */
    int ret = classical_keypair(kex->classical_alg, classical_ct, classical_eph_sk);
    if (ret == PQ_SUCCESS) {
        ret = classical_derive(kex->classical_alg, classical_ss, classical_eph_sk, classical_pk);
    }
    OPENSSL_cleanse(classical_eph_sk, sizeof(classical_eph_sk));
    
    /* PQ encapsulation, directly into the output ciphertext */
    if (ret == PQ_SUCCESS) {
        ret = pq_kem_encapsulate(kex->pq_alg, pq_ct, pq_ss, pq_pk);
    }
    
    /* Combine */
    if (ret == PQ_SUCCESS) {
        ret = combine_secrets(kex, classical_ss, classical_ss_len, pq_ss,
                              classical_ct, classical_pk_len,
                              classical_pk, classical_pk_len, ss);
    }
    
    /* Secure cleanup */
    OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
    OPENSSL_cleanse(pq_ss, sizeof(pq_ss));
    
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(ss, HYBRID_SS_BYTES);
        OPENSSL_cleanse(ct, classical_pk_len + pq_ct_len);
        return ret;
    }
    
    *ct_len = classical_pk_len + pq_ct_len;
    *ss_len = HYBRID_SS_BYTES;
    return PQ_SUCCESS;
}


int pq_hybrid_kex_decapsulate(pq_hybrid_kex_t *kex, uint8_t *ss, size_t *ss_len,
                              const uint8_t *ct, size_t ct_len,
                              const uint8_t *sk, size_t sk_len) {
    if (!kex || !ss || !ss_len || !ct || !sk) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    size_t classical_pk_len = get_classical_pk_size(kex->classical_alg);
    size_t classical_sk_len = get_classical_sk_size(kex->classical_alg);
    size_t classical_ss_len = get_classical_ss_size(kex->classical_alg);
    size_t pq_sk_len = pq_kem_secretkey_bytes(kex->pq_alg);
    size_t pq_ct_len = pq_kem_ciphertext_bytes(kex->pq_alg);
    if (classical_pk_len == 0 || pq_sk_len == 0) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Validate input lengths (exact) */
    if (sk_len != classical_sk_len + pq_sk_len) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    if (ct_len != classical_pk_len + pq_ct_len) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Split secret key and ciphertext (classical_ct is the peer's ephemeral public key) */
    const uint8_t *classical_sk = sk;
    const uint8_t *pq_sk = sk + classical_sk_len;
    const uint8_t *classical_ct = ct;
    const uint8_t *pq_ct = ct + classical_pk_len;
    
    uint8_t classical_pk[CLASSICAL_MAX_PK];
    uint8_t classical_ss[CLASSICAL_MAX_SS];
    uint8_t pq_ss[PQ_SS_BYTES];
    
    /* Classical decapsulation */
    int ret = classical_derive(kex->classical_alg, classical_ss, classical_sk, classical_ct);
    
    /* Our own classical public key is an input to the CONCAT KDF */
    if (ret == PQ_SUCCESS) {
        ret = classical_public_from_private(kex->classical_alg, classical_sk, classical_pk);
    }
    
    /* PQ decapsulation */
    if (ret == PQ_SUCCESS) {
        ret = pq_kem_decapsulate(kex->pq_alg, pq_ss, pq_ct, pq_sk);
    }
    
    /* Combine */
    if (ret == PQ_SUCCESS) {
        ret = combine_secrets(kex, classical_ss, classical_ss_len, pq_ss,
                              classical_ct, classical_pk_len,
                              classical_pk, classical_pk_len, ss);
    }
    
    /* Secure cleanup */
    OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
    OPENSSL_cleanse(pq_ss, sizeof(pq_ss));
    
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(ss, HYBRID_SS_BYTES);
        return ret;
    }
    
    *ss_len = HYBRID_SS_BYTES;
    return PQ_SUCCESS;
}

/* ========================================================================
 * Size Query Functions
 * ======================================================================== */

size_t pq_hybrid_kex_publickey_bytes(pq_hybrid_kex_t *kex) {
    if (!kex) {
        return 0;
    }
    
    size_t classical_pk_len = get_classical_pk_size(kex->classical_alg);
    size_t pq_pk_len = pq_kem_publickey_bytes(kex->pq_alg);
    
    return classical_pk_len + pq_pk_len;
}

size_t pq_hybrid_kex_secretkey_bytes(pq_hybrid_kex_t *kex) {
    if (!kex) {
        return 0;
    }
    
    size_t classical_sk_len = get_classical_sk_size(kex->classical_alg);
    size_t pq_sk_len = pq_kem_secretkey_bytes(kex->pq_alg);
    
    return classical_sk_len + pq_sk_len;
}

size_t pq_hybrid_kex_ciphertext_bytes(pq_hybrid_kex_t *kex) {
    if (!kex) {
        return 0;
    }
    
    /* Ciphertext is classical ephemeral public key + PQ ciphertext */
    size_t classical_ct_len = get_classical_pk_size(kex->classical_alg);
    size_t pq_ct_len = pq_kem_ciphertext_bytes(kex->pq_alg);
    
    return classical_ct_len + pq_ct_len;
}

size_t pq_hybrid_kex_sharedsecret_bytes(pq_hybrid_kex_t *kex) {
    if (!kex) {
        return 0;
    }
    
    if (kex->mode == HYBRID_MODE_CONCAT || kex->mode == HYBRID_MODE_XOR) {
        return HYBRID_SS_BYTES;  /* both modes produce a 32-byte secret */
    }
    
    return 0;
}
