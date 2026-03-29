/**
 * @file kem_classical.c
 * @brief Classical KEM Providers using OpenSSL EVP
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements pq_kem_provider_t for X25519 and ECDH P-256 using
 * OpenSSL 3.0 EVP API.  These providers model ECDH as a KEM:
 *   keygen()      = generate ephemeral key pair
 *   encapsulate() = generate ephemeral key pair, derive shared secret
 *   decapsulate() = derive shared secret from peer's public key
 */

#include "kem_classical.h"
#include "pq_errors.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <string.h>
#include <stdbool.h>

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
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) <= 0) goto done;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) <= 0) goto done;
    rc = PQ_SUCCESS;

done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int x25519_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    /* Generate ephemeral key pair */
    uint8_t eph_pk[X25519_PK_SIZE], eph_sk[X25519_SK_SIZE];
    int rc = x25519_keygen(eph_pk, eph_sk);
    if (rc != PQ_SUCCESS) return rc;

    /* Ciphertext is the ephemeral public key */
    memcpy(ct, eph_pk, X25519_PK_SIZE);

    /* Derive shared secret: ECDH(eph_sk, pk) */
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                   pk, X25519_PK_SIZE);
    EVP_PKEY *self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                    eph_sk, X25519_SK_SIZE);
    rc = PQ_ERR_CRYPTO_FAILED;
    if (!peer || !self) goto enc_done;

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(self, NULL);
    if (!dctx) goto enc_done;
    if (EVP_PKEY_derive_init(dctx) <= 0) { EVP_PKEY_CTX_free(dctx); goto enc_done; }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) { EVP_PKEY_CTX_free(dctx); goto enc_done; }

    size_t ss_len = X25519_SS_SIZE;
    if (EVP_PKEY_derive(dctx, ss, &ss_len) <= 0) { EVP_PKEY_CTX_free(dctx); goto enc_done; }
    rc = PQ_SUCCESS;
    EVP_PKEY_CTX_free(dctx);

enc_done:
    OPENSSL_cleanse(eph_sk, sizeof(eph_sk));
    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return rc;
}

static int x25519_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    /* ct is the peer's ephemeral public key */
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                   ct, X25519_CT_SIZE);
    EVP_PKEY *self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                    sk, X25519_SK_SIZE);
    int rc = PQ_ERR_CRYPTO_FAILED;
    if (!peer || !self) goto done;

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(self, NULL);
    if (!dctx) goto done;
    if (EVP_PKEY_derive_init(dctx) <= 0) { EVP_PKEY_CTX_free(dctx); goto done; }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) { EVP_PKEY_CTX_free(dctx); goto done; }

    size_t ss_len = X25519_SS_SIZE;
    if (EVP_PKEY_derive(dctx, ss, &ss_len) <= 0) { EVP_PKEY_CTX_free(dctx); goto done; }
    rc = PQ_SUCCESS;
    EVP_PKEY_CTX_free(dctx);

done:
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
 * ECDH P-256 Provider
 * ======================================================================== */

#define P256_PK_SIZE  65   /* uncompressed point: 0x04 || x(32) || y(32) */
#define P256_SK_SIZE  32
#define P256_CT_SIZE  65   /* ephemeral public key */
#define P256_SS_SIZE  32

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
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return PQ_ERR_KEY_GENERATION_FAILED;

    int rc = PQ_ERR_KEY_GENERATION_FAILED;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto done;

    /* Extract raw keys */
    BIGNUM *priv_bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, "priv", &priv_bn) <= 0) goto done;
    int bn_len = BN_bn2binpad(priv_bn, sk, P256_SK_SIZE);
    BN_free(priv_bn);
    if (bn_len != P256_SK_SIZE) goto done;

    size_t pk_len = P256_PK_SIZE;
    if (EVP_PKEY_get_octet_string_param(pkey, "pub", pk, P256_PK_SIZE, &pk_len) <= 0)
        goto done;

    rc = PQ_SUCCESS;

done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int p256_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    /* Generate ephemeral P-256 key pair */
    uint8_t eph_pk[P256_PK_SIZE], eph_sk[P256_SK_SIZE];
    int rc = p256_keygen(eph_pk, eph_sk);
    if (rc != PQ_SUCCESS) return rc;

    /* Ciphertext = ephemeral public key */
    memcpy(ct, eph_pk, P256_PK_SIZE);

    /* Derive shared secret via ECDH */
    EVP_PKEY *peer = EVP_PKEY_new();
    EVP_PKEY *self = EVP_PKEY_new();
    rc = PQ_ERR_CRYPTO_FAILED;

    /* Build peer key from raw public key */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) goto enc_done;
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0)) { OSSL_PARAM_BLD_free(bld); goto enc_done; }
    if (!OSSL_PARAM_BLD_push_octet_string(bld, "pub", pk, P256_PK_SIZE)) { OSSL_PARAM_BLD_free(bld); goto enc_done; }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) goto enc_done;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) { OSSL_PARAM_free(params); goto enc_done; }
    EVP_PKEY_free(peer);
    peer = NULL;
    if (EVP_PKEY_fromdata_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); OSSL_PARAM_free(params); goto enc_done; }
    if (EVP_PKEY_fromdata(pctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0) { EVP_PKEY_CTX_free(pctx); OSSL_PARAM_free(params); goto enc_done; }
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);

    /* Build self key from ephemeral private + public */
    bld = OSSL_PARAM_BLD_new();
    if (!bld) goto enc_done;
    BIGNUM *priv_bn = BN_bin2bn(eph_sk, P256_SK_SIZE, NULL);
    if (!priv_bn) { OSSL_PARAM_BLD_free(bld); goto enc_done; }
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0)) { BN_free(priv_bn); OSSL_PARAM_BLD_free(bld); goto enc_done; }
    if (!OSSL_PARAM_BLD_push_octet_string(bld, "pub", eph_pk, P256_PK_SIZE)) { BN_free(priv_bn); OSSL_PARAM_BLD_free(bld); goto enc_done; }
    if (!OSSL_PARAM_BLD_push_BN(bld, "priv", priv_bn)) { BN_free(priv_bn); OSSL_PARAM_BLD_free(bld); goto enc_done; }
    BN_free(priv_bn);

    params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) goto enc_done;

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) { OSSL_PARAM_free(params); goto enc_done; }
    EVP_PKEY_free(self);
    self = NULL;
    if (EVP_PKEY_fromdata_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); OSSL_PARAM_free(params); goto enc_done; }
    if (EVP_PKEY_fromdata(pctx, &self, EVP_PKEY_KEYPAIR, params) <= 0) { EVP_PKEY_CTX_free(pctx); OSSL_PARAM_free(params); goto enc_done; }
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);

    /* Derive */
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(self, NULL);
    if (!dctx) goto enc_done;
    if (EVP_PKEY_derive_init(dctx) <= 0) { EVP_PKEY_CTX_free(dctx); goto enc_done; }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) { EVP_PKEY_CTX_free(dctx); goto enc_done; }
    size_t ss_len = P256_SS_SIZE;
    if (EVP_PKEY_derive(dctx, ss, &ss_len) <= 0) { EVP_PKEY_CTX_free(dctx); goto enc_done; }
    EVP_PKEY_CTX_free(dctx);
    rc = PQ_SUCCESS;

enc_done:
    OPENSSL_cleanse(eph_sk, sizeof(eph_sk));
    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return rc;
}

static int p256_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    /* For decapsulation we need our full key pair; this simplified version
     * assumes the secret key buffer contains just the scalar, and the
     * public key must be derived or provided separately.
     *
     * In production TLS, OpenSSL handles this via the oqs-provider.
     * This standalone KEM wrapper is primarily for benchmarking and
     * agility-layer validation. */
    (void)sk; (void)ct; (void)ss;
    return PQ_ERR_UNSUPPORTED_ALGORITHM; /* use OpenSSL TLS path for P-256 */
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
