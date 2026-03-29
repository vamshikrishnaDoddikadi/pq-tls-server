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
#include "pq_kem.h"
#include "pq_errors.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
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
#define P256_PUBLICKEY_BYTES    65  /* Uncompressed point: 0x04 || x || y */
#define P256_SECRETKEY_BYTES    32
#define P256_SHAREDSECRET_BYTES 32

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
 * @brief Generate X25519 key pair
 */
static int x25519_keypair(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t pk_len = X25519_PUBLICKEY_BYTES;
    size_t sk_len = X25519_SECRETKEY_BYTES;
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
    
    /* Extract secret key */
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0) {
        goto cleanup;
    }
    
    ret = PQ_SUCCESS;
    
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

/**
 * @brief Derive X25519 shared secret
 */
static int x25519_derive(uint8_t *ss, const uint8_t *sk, const uint8_t *peer_pk) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t ss_len = X25519_SHAREDSECRET_BYTES;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Load our secret key */
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, X25519_SECRETKEY_BYTES);
    if (!pkey) {
        goto cleanup;
    }
    
    /* Load peer's public key */
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, X25519_PUBLICKEY_BYTES);
    if (!peer) {
        goto cleanup;
    }
    
    /* Derive shared secret */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, ss, &ss_len) <= 0) {
        goto cleanup;
    }
    
    ret = PQ_SUCCESS;
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (peer) EVP_PKEY_free(peer);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}


/* ========================================================================
 * ECDH P-256 Operations
 * ======================================================================== */

/**
 * @brief Generate ECDH P-256 key pair
 */
static int p256_keypair(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *pub_point = NULL;
    const BIGNUM *priv_bn = NULL;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Create P-256 key generation context */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        goto cleanup;
    }
    
    /* Extract EC_KEY */
    ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        goto cleanup;
    }
    
    group = EC_KEY_get0_group(ec_key);
    pub_point = EC_KEY_get0_public_key(ec_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);
    
    if (!group || !pub_point || !priv_bn) {
        goto cleanup;
    }
    
    /* Convert public key to uncompressed format (0x04 || x || y) */
    size_t pk_len = EC_POINT_point2oct(group, pub_point, 
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       pk, P256_PUBLICKEY_BYTES, NULL);
    if (pk_len != P256_PUBLICKEY_BYTES) {
        goto cleanup;
    }
    
    /* Convert private key to 32-byte big-endian */
    if (BN_bn2binpad(priv_bn, sk, P256_SECRETKEY_BYTES) != P256_SECRETKEY_BYTES) {
        goto cleanup;
    }
    
    ret = PQ_SUCCESS;
    
cleanup:
    if (ec_key) EC_KEY_free(ec_key);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return ret;
}

/**
 * @brief Derive ECDH P-256 shared secret
 */
static int p256_derive(uint8_t *ss, const uint8_t *sk, const uint8_t *peer_pk) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EC_KEY *ec_key = NULL;
    EC_KEY *peer_ec_key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *peer_point = NULL;
    BIGNUM *priv_bn = NULL;
    size_t ss_len = P256_SHAREDSECRET_BYTES;
    int ret = PQ_ERR_CRYPTO_FAILED;
    
    /* Create EC group for P-256 */
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        goto cleanup;
    }
    
    /* Load our secret key */
    ec_key = EC_KEY_new();
    if (!ec_key) {
        goto cleanup;
    }
    if (EC_KEY_set_group(ec_key, group) != 1) {
        goto cleanup;
    }
    
    priv_bn = BN_bin2bn(sk, P256_SECRETKEY_BYTES, NULL);
    if (!priv_bn) {
        goto cleanup;
    }
    if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
        goto cleanup;
    }
    
    pkey = EVP_PKEY_new();
    if (!pkey) {
        goto cleanup;
    }
    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        goto cleanup;
    }
    
    /* Load peer's public key */
    peer_ec_key = EC_KEY_new();
    if (!peer_ec_key) {
        goto cleanup;
    }
    if (EC_KEY_set_group(peer_ec_key, group) != 1) {
        goto cleanup;
    }
    
    peer_point = EC_POINT_new(group);
    if (!peer_point) {
        goto cleanup;
    }
    if (EC_POINT_oct2point(group, peer_point, peer_pk, P256_PUBLICKEY_BYTES, NULL) != 1) {
        goto cleanup;
    }
    if (EC_KEY_set_public_key(peer_ec_key, peer_point) != 1) {
        goto cleanup;
    }
    
    peer = EVP_PKEY_new();
    if (!peer) {
        goto cleanup;
    }
    if (EVP_PKEY_set1_EC_KEY(peer, peer_ec_key) != 1) {
        goto cleanup;
    }
    
    /* Derive shared secret */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, ss, &ss_len) <= 0) {
        goto cleanup;
    }
    
    ret = PQ_SUCCESS;
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (peer) EVP_PKEY_free(peer);
    if (pkey) EVP_PKEY_free(pkey);
    if (peer_point) EC_POINT_free(peer_point);
    if (peer_ec_key) EC_KEY_free(peer_ec_key);
    if (priv_bn) BN_free(priv_bn);
    if (ec_key) EC_KEY_free(ec_key);
    if (group) EC_GROUP_free(group);
    return ret;
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
    pq_hybrid_kex_t *kex = (pq_hybrid_kex_t*)malloc(sizeof(pq_hybrid_kex_t));
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
    
    /* Generate classical key pair */
    uint8_t *classical_pk = pk;
    uint8_t *classical_sk = sk;
    
    if (kex->classical_alg == HYBRID_CLASSICAL_X25519) {
        ret = x25519_keypair(classical_pk, classical_sk);
    } else if (kex->classical_alg == HYBRID_CLASSICAL_P256) {
        ret = p256_keypair(classical_pk, classical_sk);
    } else {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    if (ret != PQ_SUCCESS) {
        return ret;
    }
    
    /* Generate PQ key pair */
    uint8_t *pq_pk = pk + classical_pk_len;
    uint8_t *pq_sk = sk + classical_sk_len;
    
    ret = pq_kem_keypair(kex->pq_alg, pq_pk, pq_sk);
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(classical_sk, classical_sk_len);
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
    
    int ret;
    size_t classical_pk_len = get_classical_pk_size(kex->classical_alg);
    size_t classical_ss_len = get_classical_ss_size(kex->classical_alg);
    size_t pq_pk_len = pq_kem_publickey_bytes(kex->pq_alg);
    size_t pq_ct_len = pq_kem_ciphertext_bytes(kex->pq_alg);
    
    /* Validate input public key length */
    if (pk_len != classical_pk_len + pq_pk_len) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Split public key */
    const uint8_t *classical_pk = pk;
    const uint8_t *pq_pk = pk + classical_pk_len;
    
    /* Classical encapsulation (generate ephemeral key and derive) */
    uint8_t classical_eph_sk[P256_SECRETKEY_BYTES];
    uint8_t classical_ct[P256_PUBLICKEY_BYTES];
    uint8_t classical_ss[P256_SHAREDSECRET_BYTES];
    size_t classical_ct_len;
    
    /* Generate ephemeral classical key pair */
    if (kex->classical_alg == HYBRID_CLASSICAL_X25519) {
        ret = x25519_keypair(classical_ct, classical_eph_sk);
        classical_ct_len = X25519_PUBLICKEY_BYTES;
    } else if (kex->classical_alg == HYBRID_CLASSICAL_P256) {
        ret = p256_keypair(classical_ct, classical_eph_sk);
        classical_ct_len = P256_PUBLICKEY_BYTES;
    } else {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    if (ret != PQ_SUCCESS) {
        return ret;
    }
    
    /* Derive classical shared secret */
    if (kex->classical_alg == HYBRID_CLASSICAL_X25519) {
        ret = x25519_derive(classical_ss, classical_eph_sk, classical_pk);
    } else if (kex->classical_alg == HYBRID_CLASSICAL_P256) {
        ret = p256_derive(classical_ss, classical_eph_sk, classical_pk);
    } else {
        OPENSSL_cleanse(classical_eph_sk, sizeof(classical_eph_sk));
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    OPENSSL_cleanse(classical_eph_sk, sizeof(classical_eph_sk));
    
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
        return ret;
    }
    
    /* PQ encapsulation */
    uint8_t pq_ct[2000];
    uint8_t pq_ss[32];
    
    ret = pq_kem_encapsulate(kex->pq_alg, pq_ct, pq_ss, pq_pk);
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
        return ret;
    }
    
    /* Combine ciphertext (always concatenated) */
    memcpy(ct, classical_ct, classical_ct_len);
    memcpy(ct + classical_ct_len, pq_ct, pq_ct_len);
    *ct_len = classical_ct_len + pq_ct_len;
    
    /* Combine shared secret based on mode */
    if (kex->mode == HYBRID_MODE_CONCAT) {
        memcpy(ss, classical_ss, classical_ss_len);
        memcpy(ss + classical_ss_len, pq_ss, 32);
        *ss_len = classical_ss_len + 32;
    } else if (kex->mode == HYBRID_MODE_XOR) {
        /* XOR shared secrets (both are 32 bytes) */
        for (size_t i = 0; i < 32; i++) {
            ss[i] = classical_ss[i] ^ pq_ss[i];
        }
        *ss_len = 32;
    } else {
        OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
        OPENSSL_cleanse(pq_ss, sizeof(pq_ss));
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Secure cleanup */
    OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
    OPENSSL_cleanse(pq_ss, sizeof(pq_ss));
    
    return PQ_SUCCESS;
}


int pq_hybrid_kex_decapsulate(pq_hybrid_kex_t *kex, uint8_t *ss, size_t *ss_len,
                              const uint8_t *ct, size_t ct_len,
                              const uint8_t *sk, size_t sk_len) {
    if (!kex || !ss || !ss_len || !ct || !sk) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    int ret;
    size_t classical_pk_len = get_classical_pk_size(kex->classical_alg);
    size_t classical_sk_len = get_classical_sk_size(kex->classical_alg);
    size_t classical_ss_len = get_classical_ss_size(kex->classical_alg);
    size_t pq_sk_len = pq_kem_secretkey_bytes(kex->pq_alg);
    size_t pq_ct_len = pq_kem_ciphertext_bytes(kex->pq_alg);
    
    /* Validate input lengths */
    if (sk_len != classical_sk_len + pq_sk_len) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    if (ct_len != classical_pk_len + pq_ct_len) {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Split secret key */
    const uint8_t *classical_sk = sk;
    const uint8_t *pq_sk = sk + classical_sk_len;
    
    /* Split ciphertext (classical_ct is peer's ephemeral public key) */
    const uint8_t *classical_ct = ct;
    const uint8_t *pq_ct = ct + classical_pk_len;
    
    /* Classical decapsulation (derive shared secret from ephemeral public key) */
    uint8_t classical_ss[P256_SHAREDSECRET_BYTES];
    
    if (kex->classical_alg == HYBRID_CLASSICAL_X25519) {
        ret = x25519_derive(classical_ss, classical_sk, classical_ct);
    } else if (kex->classical_alg == HYBRID_CLASSICAL_P256) {
        ret = p256_derive(classical_ss, classical_sk, classical_ct);
    } else {
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
        return ret;
    }
    
    /* PQ decapsulation */
    uint8_t pq_ss[32];
    
    ret = pq_kem_decapsulate(kex->pq_alg, pq_ss, pq_ct, pq_sk);
    if (ret != PQ_SUCCESS) {
        OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
        return ret;
    }
    
    /* Combine shared secret based on mode */
    if (kex->mode == HYBRID_MODE_CONCAT) {
        memcpy(ss, classical_ss, classical_ss_len);
        memcpy(ss + classical_ss_len, pq_ss, 32);
        *ss_len = classical_ss_len + 32;
    } else if (kex->mode == HYBRID_MODE_XOR) {
        /* XOR shared secrets (both are 32 bytes) */
        for (size_t i = 0; i < 32; i++) {
            ss[i] = classical_ss[i] ^ pq_ss[i];
        }
        *ss_len = 32;
    } else {
        OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
        OPENSSL_cleanse(pq_ss, sizeof(pq_ss));
        return PQ_ERR_INVALID_PARAMETER;
    }
    
    /* Secure cleanup */
    OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
    OPENSSL_cleanse(pq_ss, sizeof(pq_ss));
    
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
    
    if (kex->mode == HYBRID_MODE_CONCAT) {
        size_t classical_ss_len = get_classical_ss_size(kex->classical_alg);
        return classical_ss_len + 32;  /* PQ shared secret is always 32 bytes */
    } else if (kex->mode == HYBRID_MODE_XOR) {
        return 32;  /* XOR mode produces fixed 32-byte shared secret */
    }
    
    return 0;
}
