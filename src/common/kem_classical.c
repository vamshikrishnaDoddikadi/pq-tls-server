/**
 * @file kem_classical.c
 * @brief Classical KEM Providers using OpenSSL EVP
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements pq_kem_provider_t for X25519 and ECDH P-256 using the
 * OpenSSL 3.0 EVP / OSSL_PARAM APIs (no deprecated EC_KEY calls).
 * These providers model ECDH as a KEM:
 *   keygen()      = generate key pair
 *   encapsulate() = generate ephemeral key pair, derive shared secret;
 *                   the ephemeral public key is the ciphertext
 *   decapsulate() = derive shared secret from the peer's ephemeral key
 *
 * Note: the raw ECDH output is returned as the "shared secret".  It is NOT
 * a uniformly random key and must be fed through a KDF / combiner before use.
 */

#include "kem_classical.h"
#include "pq_errors.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <string.h>
#include <stdbool.h>

/* ========================================================================
 * Shared EVP derive helper
 * ======================================================================== */

static int evp_derive_exact(EVP_PKEY *self, EVP_PKEY *peer, uint8_t *out, size_t expected)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(self, NULL);
    size_t out_len = expected;
    int rc = PQ_ERR_CRYPTO_FAILED;

    if (!ctx) return PQ_ERR_CRYPTO_FAILED;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0 || out_len != expected) goto done;
    rc = PQ_SUCCESS;

done:
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(out, expected);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* ========================================================================
 * X25519 Provider
 * ======================================================================== */

#define X25519_PK_SIZE  32
#define X25519_SK_SIZE  32
#define X25519_CT_SIZE  32   /* ephemeral public key serves as ciphertext */
#define X25519_SS_SIZE  32

static const char *x25519_name(void) { return "X25519"; }

static const pq_algorithm_metadata_t x25519_meta = {
    .name       = "X25519",
    .oid        = "1.3.101.110",
    .tls_group  = "X25519",
    .family     = PQ_ALG_FAMILY_CLASSICAL,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 1,
    .pk_size    = X25519_PK_SIZE,
    .sk_size    = X25519_SK_SIZE,
    .ct_size    = X25519_CT_SIZE,
    .ss_size    = X25519_SS_SIZE,
};

static const pq_algorithm_metadata_t *x25519_metadata(void) { return &x25519_meta; }

static int x25519_keygen(uint8_t *pk, uint8_t *sk)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return PQ_ERR_KEY_GENERATION_FAILED;

    int rc = PQ_ERR_KEY_GENERATION_FAILED;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto done;

    size_t pk_len = X25519_PK_SIZE, sk_len = X25519_SK_SIZE;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0 || pk_len != X25519_PK_SIZE) goto done;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0 || sk_len != X25519_SK_SIZE) goto done;
    rc = PQ_SUCCESS;

done:
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(sk, X25519_SK_SIZE);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int x25519_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    /* Generate ephemeral key pair; the ephemeral public key is the ciphertext */
    uint8_t eph_sk[X25519_SK_SIZE];
    int rc = x25519_keygen(ct, eph_sk);
    if (rc != PQ_SUCCESS) return rc;

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk, X25519_PK_SIZE);
    EVP_PKEY *self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, eph_sk, X25519_SK_SIZE);
    OPENSSL_cleanse(eph_sk, sizeof(eph_sk));

    /* OpenSSL rejects low-order peer points (all-zero output) in derive */
    rc = (peer && self) ? evp_derive_exact(self, peer, ss, X25519_SS_SIZE)
                        : PQ_ERR_CRYPTO_FAILED;

    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return rc;
}

static int x25519_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    /* ct is the peer's ephemeral public key */
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ct, X25519_CT_SIZE);
    EVP_PKEY *self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, X25519_SK_SIZE);

    int rc = (peer && self) ? evp_derive_exact(self, peer, ss, X25519_SS_SIZE)
                            : PQ_ERR_CRYPTO_FAILED;

    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return rc;
}

static bool x25519_is_available(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return false;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

static void x25519_cleanup(void) { }

static const pq_kem_provider_t x25519_provider = {
    .name          = x25519_name,
    .metadata      = x25519_metadata,
    .keygen        = x25519_keygen,
    .encapsulate   = x25519_encapsulate,
    .decapsulate   = x25519_decapsulate,
    .is_available  = x25519_is_available,
    .cleanup       = x25519_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_x25519(void)
{
    return &x25519_provider;
}

/* ========================================================================
 * Raw P-256 helpers (exported via kem_classical.h)
 * ======================================================================== */

#define P256_GROUP_NAME SN_X9_62_prime256v1   /* "prime256v1" */

int pq_p256_public_from_private(const uint8_t sk[PQ_P256_SECRETKEY_BYTES],
                                uint8_t pk[PQ_P256_PUBLICKEY_BYTES])
{
    EC_GROUP *group = NULL;
    BN_CTX *bnctx = NULL;
    BIGNUM *d = NULL;
    EC_POINT *point = NULL;
    int rc = PQ_ERR_CRYPTO_FAILED;

    if (!sk || !pk) return PQ_ERR_NULL_POINTER;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bnctx = BN_CTX_secure_new();
    d = BN_secure_new();
    if (!group || !bnctx || !d) goto done;
    BN_set_flags(d, BN_FLG_CONSTTIME);
    if (!BN_bin2bn(sk, PQ_P256_SECRETKEY_BYTES, d)) goto done;

    /* Private scalar must satisfy 1 <= d < n */
    if (BN_is_zero(d) || BN_cmp(d, EC_GROUP_get0_order(group)) >= 0) {
        rc = PQ_ERR_INVALID_PARAMETER;
        goto done;
    }

    point = EC_POINT_new(group);
    if (!point) goto done;
    if (EC_POINT_mul(group, point, d, NULL, NULL, bnctx) != 1) goto done;
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                           pk, PQ_P256_PUBLICKEY_BYTES, bnctx) != PQ_P256_PUBLICKEY_BYTES)
        goto done;
    rc = PQ_SUCCESS;

done:
    EC_POINT_clear_free(point);
    BN_clear_free(d);
    BN_CTX_free(bnctx);
    EC_GROUP_free(group);
    return rc;
}

/* Import (optional private scalar, public point) as an EVP_PKEY. */
static int p256_import(const uint8_t *sk, const uint8_t pk[PQ_P256_PUBLICKEY_BYTES],
                       EVP_PKEY **out)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *d = NULL;
    int selection = sk ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
    int rc = PQ_ERR_CRYPTO_FAILED;

    *out = NULL;
    if (!bld) return PQ_ERR_MEMORY_ALLOCATION;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, P256_GROUP_NAME, 0))
        goto done;
    if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          pk, PQ_P256_PUBLICKEY_BYTES))
        goto done;
    if (sk) {
        /* A secure BIGNUM makes the param builder place the scalar in the
         * secure (cleared-on-free) part of the OSSL_PARAM block. */
        d = BN_secure_new();
        if (!d || !BN_bin2bn(sk, PQ_P256_SECRETKEY_BYTES, d)) goto done;
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d)) goto done;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto done;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) goto done;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto done;
    if (EVP_PKEY_fromdata(ctx, out, selection, params) <= 0) {
        *out = NULL;
        goto done;
    }
    rc = PQ_SUCCESS;

done:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);        /* clears the secure part holding d */
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(d);
    return rc;
}

int pq_p256_pkey_from_public(const uint8_t pk[PQ_P256_PUBLICKEY_BYTES], EVP_PKEY **out)
{
    if (!pk || !out) return PQ_ERR_NULL_POINTER;
    *out = NULL;

    /* Only the uncompressed SEC1 encoding is accepted */
    if (pk[0] != 0x04) return PQ_ERR_INVALID_FORMAT;

    EVP_PKEY *key = NULL;
    int rc = p256_import(NULL, pk, &key);
    if (rc != PQ_SUCCESS) return PQ_ERR_INVALID_FORMAT;

    /* SECURITY: explicit point validation (on curve, not the identity).
     * P-256 has cofactor 1, so the quick check is a full validation and
     * prevents invalid-curve attacks.  CWE-295 / CWE-347 */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx || EVP_PKEY_public_check_quick(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return PQ_ERR_INVALID_FORMAT;
    }
    EVP_PKEY_CTX_free(ctx);

    *out = key;
    return PQ_SUCCESS;
}

int pq_p256_pkey_from_private(const uint8_t sk[PQ_P256_SECRETKEY_BYTES], EVP_PKEY **out)
{
    uint8_t pk[PQ_P256_PUBLICKEY_BYTES];

    if (!sk || !out) return PQ_ERR_NULL_POINTER;
    *out = NULL;

    /* OpenSSL 3.0 cannot run ECDH/ECDSA reliably on a private-only EC key
     * imported via fromdata, so recompute and import the public point too. */
    int rc = pq_p256_public_from_private(sk, pk);
    if (rc == PQ_SUCCESS) rc = p256_import(sk, pk, out);
    return rc;
}

int pq_p256_generate_raw(uint8_t pk[PQ_P256_PUBLICKEY_BYTES],
                         uint8_t sk[PQ_P256_SECRETKEY_BYTES])
{
    EVP_PKEY *pkey = NULL;
    BIGNUM *d = NULL;
    size_t pk_len = 0;
    int rc = PQ_ERR_KEY_GENERATION_FAILED;

    if (!pk || !sk) return PQ_ERR_NULL_POINTER;

    pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!pkey) goto done;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d) != 1) goto done;
    if (BN_bn2binpad(d, sk, PQ_P256_SECRETKEY_BYTES) != PQ_P256_SECRETKEY_BYTES) goto done;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pk, PQ_P256_PUBLICKEY_BYTES, &pk_len) != 1)
        goto done;
    if (pk_len != PQ_P256_PUBLICKEY_BYTES || pk[0] != 0x04) goto done;

    rc = PQ_SUCCESS;

done:
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(sk, PQ_P256_SECRETKEY_BYTES);
    BN_clear_free(d);
    EVP_PKEY_free(pkey);
    return rc;
}

int pq_p256_ecdh_raw(const uint8_t sk[PQ_P256_SECRETKEY_BYTES],
                     const uint8_t peer_pk[PQ_P256_PUBLICKEY_BYTES],
                     uint8_t ss[PQ_P256_SHAREDSECRET_BYTES])
{
    EVP_PKEY *self = NULL, *peer = NULL;

    if (!sk || !peer_pk || !ss) return PQ_ERR_NULL_POINTER;

    int rc = pq_p256_pkey_from_public(peer_pk, &peer);
    if (rc == PQ_SUCCESS) rc = pq_p256_pkey_from_private(sk, &self);
    if (rc == PQ_SUCCESS) rc = evp_derive_exact(self, peer, ss, PQ_P256_SHAREDSECRET_BYTES);

    if (rc != PQ_SUCCESS) OPENSSL_cleanse(ss, PQ_P256_SHAREDSECRET_BYTES);
    EVP_PKEY_free(self);
    EVP_PKEY_free(peer);
    return rc;
}

/* ========================================================================
 * ECDH P-256 Provider
 * ======================================================================== */

#define P256_PK_SIZE  PQ_P256_PUBLICKEY_BYTES   /* 0x04 || x(32) || y(32) */
#define P256_SK_SIZE  PQ_P256_SECRETKEY_BYTES
#define P256_CT_SIZE  PQ_P256_PUBLICKEY_BYTES   /* ephemeral public key */
#define P256_SS_SIZE  PQ_P256_SHAREDSECRET_BYTES

static const char *p256_name(void) { return "P-256"; }

static const pq_algorithm_metadata_t p256_meta = {
    .name       = "P-256",
    .oid        = "1.2.840.10045.3.1.7",
    .tls_group  = "P-256",
    .family     = PQ_ALG_FAMILY_CLASSICAL,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 1,
    .pk_size    = P256_PK_SIZE,
    .sk_size    = P256_SK_SIZE,
    .ct_size    = P256_CT_SIZE,
    .ss_size    = P256_SS_SIZE,
};

static const pq_algorithm_metadata_t *p256_metadata(void) { return &p256_meta; }

static int p256_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_p256_generate_raw(pk, sk);
}

static int p256_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    EVP_PKEY *eph = NULL, *peer = NULL;
    size_t ct_len = 0;

    /* Validate the recipient's public key before doing anything else */
    int rc = pq_p256_pkey_from_public(pk, &peer);
    if (rc != PQ_SUCCESS) return rc;

    /* Ephemeral key pair; its public key is the ciphertext */
    eph = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!eph) { rc = PQ_ERR_KEY_GENERATION_FAILED; goto done; }

    if (EVP_PKEY_get_octet_string_param(eph, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        ct, P256_CT_SIZE, &ct_len) != 1 ||
        ct_len != P256_CT_SIZE || ct[0] != 0x04) {
        rc = PQ_ERR_CRYPTO_FAILED;
        goto done;
    }

    rc = evp_derive_exact(eph, peer, ss, P256_SS_SIZE);

done:
    EVP_PKEY_free(eph);
    EVP_PKEY_free(peer);
    return rc;
}

static int p256_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    /* ct is the peer's ephemeral public key (validated inside) */
    return pq_p256_ecdh_raw(sk, ct, ss);
}

static bool p256_is_available(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return false;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

static void p256_cleanup(void) { }

static const pq_kem_provider_t p256_provider = {
    .name          = p256_name,
    .metadata      = p256_metadata,
    .keygen        = p256_keygen,
    .encapsulate   = p256_encapsulate,
    .decapsulate   = p256_decapsulate,
    .is_available  = p256_is_available,
    .cleanup       = p256_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_p256(void)
{
    return &p256_provider;
}
