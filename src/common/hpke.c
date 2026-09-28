/**
 * @file hpke.c
 * @brief RFC 9180 Hybrid Public Key Encryption (Base mode) implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * Implements RFC 9180 HPKE Base mode with HKDF-SHA256:
 *   - LabeledExtract / LabeledExpand ("HPKE-v1" || suite_id || label ...)
 *   - DHKEM(X25519, HKDF-SHA256) with ExtractAndExpand (section 4.1)
 *   - ML-KEM-768 used directly as a KEM
 *   - an X-Wing-style X25519 + ML-KEM-768 hybrid (private codepoint; see
 *     hpke.h for why it is not interoperable)
 *   - the key schedule (section 5.1), nonce = base_nonce XOR seq (5.2) and
 *     the secret exporter (5.3)
 *
 * All secret intermediates are wiped with OPENSSL_cleanse().
 */

#include "hpke.h"
#include "hybrid_combiner.h"
#include "pq_errors.h"
#include "pq_kem.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The HPKE ML-KEM-768 constants must agree with pq_kem.h, which is the
 * layer that talks to liboqs (and checks the sizes against liboqs at
 * runtime). */
_Static_assert(HPKE_MLKEM768_PUBLICKEY_BYTES == PQ_KEM_MLKEM768_PUBLICKEY_BYTES,
               "ML-KEM-768 public key size mismatch");
_Static_assert(HPKE_MLKEM768_SECRETKEY_BYTES == PQ_KEM_MLKEM768_SECRETKEY_BYTES,
               "ML-KEM-768 secret key size mismatch");
_Static_assert(HPKE_MLKEM768_ENCAPSULATED_BYTES == PQ_KEM_MLKEM768_CIPHERTEXT_BYTES,
               "ML-KEM-768 ciphertext size mismatch");
_Static_assert(HPKE_MLKEM768_SHAREDSECRET_BYTES == PQ_KEM_MLKEM768_SHAREDSECRET_BYTES,
               "ML-KEM-768 shared secret size mismatch");

/* ========================================================================
 * Constants and context
 * ======================================================================== */

#define HPKE_NH           32   /* HKDF-SHA256 output length */
#define HPKE_NSECRET      32   /* KEM shared secret length for every KEM here */
#define HPKE_MAX_NK       32   /* largest AEAD key (AES-256 / ChaCha20) */
#define HPKE_KEM_SUITE_ID_LEN  5   /* "KEM"  || I2OSP(kem_id, 2) */
#define HPKE_SUITE_ID_LEN     10   /* "HPKE" || kem_id || kdf_id || aead_id */

enum {
    HPKE_ROLE_NONE = 0,
    HPKE_ROLE_SENDER = 1,
    HPKE_ROLE_RECIPIENT = 2
};

struct pq_hpke_t {
    int kem;
    int aead;
    int role;
    size_t key_len;
    uint8_t key[HPKE_MAX_NK];
    uint8_t base_nonce[HPKE_AEAD_NONCE_BYTES];
    uint8_t exporter_secret[HPKE_NH];
    uint64_t seq;
};

static const uint8_t HPKE_V1_LABEL[7] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };

/* ========================================================================
 * Size queries
 * ======================================================================== */

size_t pq_hpke_publickey_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:                 return HPKE_X25519_PUBLICKEY_BYTES;
        case HPKE_KEM_MLKEM768:               return HPKE_MLKEM768_PUBLICKEY_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT: return HPKE_HYBRID_PUBLICKEY_BYTES;
        default:                              return 0;
    }
}

size_t pq_hpke_secretkey_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:                 return HPKE_X25519_SECRETKEY_BYTES;
        case HPKE_KEM_MLKEM768:               return HPKE_MLKEM768_SECRETKEY_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT: return HPKE_HYBRID_SECRETKEY_BYTES;
        default:                              return 0;
    }
}

size_t pq_hpke_encapsulated_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:                 return HPKE_X25519_ENCAPSULATED_BYTES;
        case HPKE_KEM_MLKEM768:               return HPKE_MLKEM768_ENCAPSULATED_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT: return HPKE_HYBRID_ENCAPSULATED_BYTES;
        default:                              return 0;
    }
}

size_t pq_hpke_sharedsecret_bytes(int kem) {
    switch (kem) {
        case HPKE_KEM_X25519:                 return HPKE_X25519_SHAREDSECRET_BYTES;
        case HPKE_KEM_MLKEM768:               return HPKE_MLKEM768_SHAREDSECRET_BYTES;
        case HPKE_KEM_X25519_MLKEM768_CONCAT: return HPKE_HYBRID_SHAREDSECRET_BYTES;
        default:                              return 0;
    }
}

static size_t aead_key_bytes(int aead) {
    switch (aead) {
        case HPKE_AEAD_AES128GCM:  return 16;
        case HPKE_AEAD_AES256GCM:  return 32;
        case HPKE_AEAD_CHACHAPOLY: return 32;
        default:                   return 0;
    }
}

static const EVP_CIPHER *aead_cipher(int aead) {
    switch (aead) {
        case HPKE_AEAD_AES128GCM:  return EVP_aes_128_gcm();
        case HPKE_AEAD_AES256GCM:  return EVP_aes_256_gcm();
        case HPKE_AEAD_CHACHAPOLY: return EVP_chacha20_poly1305();
        default:                   return NULL;
    }
}

/* ========================================================================
 * HKDF-SHA256 over scatter lists, and the RFC 9180 labeled variants
 * ======================================================================== */

typedef struct {
    const uint8_t *p;
    size_t n;
} hpke_iov_t;

static int hmac_sha256_iov(const uint8_t *key, size_t key_len,
                           const hpke_iov_t *iov, size_t n_iov,
                           uint8_t out[HPKE_NH]) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    size_t out_len = 0;
    int rc = PQ_ERR_CRYPTO_FAILED;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (!ctx) goto done;
    if (EVP_MAC_init(ctx, key, key_len, params) != 1) goto done;
    for (size_t i = 0; i < n_iov; i++) {
        if (iov[i].n == 0) continue;
        if (!iov[i].p) { rc = PQ_ERR_NULL_POINTER; goto done; }
        if (EVP_MAC_update(ctx, iov[i].p, iov[i].n) != 1) goto done;
    }
    if (EVP_MAC_final(ctx, out, &out_len, HPKE_NH) != 1 || out_len != HPKE_NH) goto done;
    rc = PQ_SUCCESS;

done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(out, HPKE_NH);
    return rc;
}

/* HKDF-Extract(salt, IKM); an empty salt means Nh zero bytes (RFC 5869). */
static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                        const hpke_iov_t *ikm, size_t n_ikm,
                        uint8_t prk[HPKE_NH]) {
    static const uint8_t zero_salt[HPKE_NH] = { 0 };
    if (salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    return hmac_sha256_iov(salt, salt_len, ikm, n_ikm, prk);
}

/* HKDF-Expand(PRK, info, L) with info given as a scatter list. */
#define HKDF_MAX_INFO_PARTS 6
static int hkdf_expand(const uint8_t prk[HPKE_NH],
                       const hpke_iov_t *info, size_t n_info,
                       uint8_t *out, size_t out_len) {
    uint8_t t[HPKE_NH];
    size_t t_len = 0, off = 0;
    uint8_t counter = 0;
    hpke_iov_t iov[HKDF_MAX_INFO_PARTS + 2];
    int rc = PQ_SUCCESS;

    if (out_len == 0 || out_len > 255u * HPKE_NH || n_info > HKDF_MAX_INFO_PARTS)
        return PQ_ERR_INVALID_PARAMETER;

    while (off < out_len) {
        size_t k = 0;
        counter++;
        iov[k].p = t;
        iov[k++].n = t_len;
        for (size_t i = 0; i < n_info; i++) iov[k++] = info[i];
        iov[k].p = &counter;
        iov[k++].n = 1;

        rc = hmac_sha256_iov(prk, HPKE_NH, iov, k, t);
        if (rc != PQ_SUCCESS) {
            OPENSSL_cleanse(out, out_len);
            break;
        }
        t_len = HPKE_NH;
        size_t take = (out_len - off < HPKE_NH) ? out_len - off : HPKE_NH;
        memcpy(out + off, t, take);
        off += take;
    }
    OPENSSL_cleanse(t, sizeof(t));
    return rc;
}

/* LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm) */
static int labeled_extract(const uint8_t *suite_id, size_t suite_id_len,
                           const uint8_t *salt, size_t salt_len,
                           const char *label,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk[HPKE_NH]) {
    const hpke_iov_t parts[] = {
        { HPKE_V1_LABEL, sizeof(HPKE_V1_LABEL) },
        { suite_id, suite_id_len },
        { (const uint8_t *)label, strlen(label) },
        { ikm, ikm_len },
    };
    return hkdf_extract(salt, salt_len, parts, sizeof(parts) / sizeof(parts[0]), prk);
}

/* LabeledExpand(prk, label, info, L) =
 *   Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L) */
static int labeled_expand(const uint8_t *suite_id, size_t suite_id_len,
                          const uint8_t prk[HPKE_NH],
                          const char *label,
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len) {
    if (out_len > 0xFFFFu) return PQ_ERR_INVALID_PARAMETER;
    const uint8_t l2[2] = { (uint8_t)(out_len >> 8), (uint8_t)out_len };
    const hpke_iov_t parts[] = {
        { l2, sizeof(l2) },
        { HPKE_V1_LABEL, sizeof(HPKE_V1_LABEL) },
        { suite_id, suite_id_len },
        { (const uint8_t *)label, strlen(label) },
        { info, info_len },
    };
    return hkdf_expand(prk, parts, sizeof(parts) / sizeof(parts[0]), out, out_len);
}

static void kem_suite_id(int kem, uint8_t out[HPKE_KEM_SUITE_ID_LEN]) {
    out[0] = 'K'; out[1] = 'E'; out[2] = 'M';
    out[3] = (uint8_t)(kem >> 8);
    out[4] = (uint8_t)kem;
}

static void hpke_suite_id(const pq_hpke_t *h, uint8_t out[HPKE_SUITE_ID_LEN]) {
    out[0] = 'H'; out[1] = 'P'; out[2] = 'K'; out[3] = 'E';
    out[4] = (uint8_t)(h->kem >> 8);
    out[5] = (uint8_t)h->kem;
    out[6] = (uint8_t)(HPKE_KDF_HKDF_SHA256 >> 8);
    out[7] = (uint8_t)HPKE_KDF_HKDF_SHA256;
    out[8] = (uint8_t)(h->aead >> 8);
    out[9] = (uint8_t)h->aead;
}

/* ========================================================================
 * X25519 primitives (OpenSSL EVP, non-deprecated APIs only)
 * ======================================================================== */

static int x25519_public_from_private(const uint8_t sk[32], uint8_t pk[32]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    size_t len = 32;
    int rc = PQ_ERR_CRYPTO_FAILED;

    if (key && EVP_PKEY_get_raw_public_key(key, pk, &len) == 1 && len == 32)
        rc = PQ_SUCCESS;
    EVP_PKEY_free(key);
    return rc;
}

static int x25519_generate(uint8_t sk[32], uint8_t pk[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    size_t sk_len = 32, pk_len = 32;
    int rc = PQ_ERR_KEY_GENERATION_FAILED;

    if (!ctx) goto done;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) goto done;
    if (EVP_PKEY_get_raw_private_key(key, sk, &sk_len) != 1 || sk_len != 32) goto done;
    if (EVP_PKEY_get_raw_public_key(key, pk, &pk_len) != 1 || pk_len != 32) goto done;
    rc = PQ_SUCCESS;

done:
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(sk, 32);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* DH(sk, pk) = X25519(sk, pk); rejects the all-zero output (RFC 9180 7.1.4). */
static int x25519_dh(const uint8_t sk[32], const uint8_t peer_pk[32], uint8_t out[32]) {
    EVP_PKEY *self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, 32);
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len = 32;
    int rc = PQ_ERR_CRYPTO_FAILED;

    if (!self || !peer) goto done;
    ctx = EVP_PKEY_CTX_new(self, NULL);
    if (!ctx) goto done;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0 || out_len != 32) goto done;

    /* Constant-time all-zero check (OpenSSL also rejects it, belt and braces). */
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++) acc |= out[i];
    if (acc == 0) goto done;

    rc = PQ_SUCCESS;

done:
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(out, 32);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return rc;
}

/* ========================================================================
 * DHKEM(X25519, HKDF-SHA256) - RFC 9180 section 4.1
 * ======================================================================== */

static int dhkem_extract_and_expand(const uint8_t dh[32],
                                    const uint8_t *kem_context, size_t kem_context_len,
                                    uint8_t ss[HPKE_NSECRET]) {
    uint8_t sid[HPKE_KEM_SUITE_ID_LEN];
    uint8_t eae_prk[HPKE_NH];
    kem_suite_id(HPKE_KEM_X25519, sid);

    int rc = labeled_extract(sid, sizeof(sid), NULL, 0, "eae_prk", dh, 32, eae_prk);
    if (rc == PQ_SUCCESS)
        rc = labeled_expand(sid, sizeof(sid), eae_prk, "shared_secret",
                            kem_context, kem_context_len, ss, HPKE_NSECRET);
    OPENSSL_cleanse(eae_prk, sizeof(eae_prk));
    return rc;
}

/* DeriveKeyPair(ikm) for X25519 (RFC 9180 section 7.1.3). */
static int dhkem_x25519_derive_keypair(const uint8_t *ikm, size_t ikm_len,
                                       uint8_t sk[32], uint8_t pk[32]) {
    uint8_t sid[HPKE_KEM_SUITE_ID_LEN];
    uint8_t dkp_prk[HPKE_NH];
    kem_suite_id(HPKE_KEM_X25519, sid);

    int rc = labeled_extract(sid, sizeof(sid), NULL, 0, "dkp_prk", ikm, ikm_len, dkp_prk);
    if (rc == PQ_SUCCESS)
        rc = labeled_expand(sid, sizeof(sid), dkp_prk, "sk", NULL, 0, sk, 32);
    if (rc == PQ_SUCCESS)
        rc = x25519_public_from_private(sk, pk);
    OPENSSL_cleanse(dkp_prk, sizeof(dkp_prk));
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(sk, 32);
    return rc;
}

/* Encap given an ephemeral key pair (skE, pkE). */
static int dhkem_x25519_encap_with(const uint8_t skE[32], const uint8_t pkE[32],
                                   const uint8_t pkR[32],
                                   uint8_t enc[32], uint8_t ss[HPKE_NSECRET]) {
    uint8_t dh[32];
    uint8_t kem_context[64];

    int rc = x25519_dh(skE, pkR, dh);
    if (rc == PQ_SUCCESS) {
        memcpy(kem_context, pkE, 32);        /* enc  = SerializePublicKey(pkE) */
        memcpy(kem_context + 32, pkR, 32);   /* pkRm = SerializePublicKey(pkR) */
        rc = dhkem_extract_and_expand(dh, kem_context, sizeof(kem_context), ss);
    }
    if (rc == PQ_SUCCESS) memcpy(enc, pkE, 32);
    OPENSSL_cleanse(dh, sizeof(dh));
    return rc;
}

static int dhkem_x25519_decap(const uint8_t enc[32], const uint8_t skR[32],
                              uint8_t ss[HPKE_NSECRET]) {
    uint8_t dh[32];
    uint8_t kem_context[64];

    int rc = x25519_dh(skR, enc, dh);
    if (rc == PQ_SUCCESS) {
        memcpy(kem_context, enc, 32);
        rc = x25519_public_from_private(skR, kem_context + 32);  /* pkRm */
    }
    if (rc == PQ_SUCCESS)
        rc = dhkem_extract_and_expand(dh, kem_context, sizeof(kem_context), ss);
    OPENSSL_cleanse(dh, sizeof(dh));
    return rc;
}

/* ========================================================================
 * X-Wing-style hybrid KEM (X25519 || ML-KEM-768 layout, private codepoint)
 *
 *   pk  = pk_X (32) || pk_M (1184)
 *   sk  = sk_X (32) || sk_M (2400)
 *   enc = ct_X (32) || ct_M (1088)
 *   ss  = SHA3-256(ss_M || ss_X || ct_X || pk_X || "\.//^\")
 * ======================================================================== */

static int xwing_style_encap(const uint8_t *pk, uint8_t *enc, uint8_t ss[HPKE_NSECRET]) {
    const uint8_t *pk_X = pk;
    const uint8_t *pk_M = pk + HPKE_X25519_PUBLICKEY_BYTES;
    uint8_t *ct_X = enc;
    uint8_t *ct_M = enc + HPKE_X25519_ENCAPSULATED_BYTES;
    uint8_t ek_X[32], ss_X[32], ss_M[32];

    int rc = x25519_generate(ek_X, ct_X);
    if (rc == PQ_SUCCESS) rc = x25519_dh(ek_X, pk_X, ss_X);
    if (rc == PQ_SUCCESS) rc = pq_kem_encapsulate(PQ_KEM_MLKEM768, ct_M, ss_M, pk_M);
    if (rc == PQ_SUCCESS)
        rc = pq_combiner_xwing_style(ss_M, sizeof(ss_M), ss_X, sizeof(ss_X),
                                     ct_X, 32, pk_X, 32,
                                     (const uint8_t *)PQ_XWING_LABEL, PQ_XWING_LABEL_BYTES,
                                     ss);
    OPENSSL_cleanse(ek_X, sizeof(ek_X));
    OPENSSL_cleanse(ss_X, sizeof(ss_X));
    OPENSSL_cleanse(ss_M, sizeof(ss_M));
    return rc;
}

static int xwing_style_decap(const uint8_t *enc, const uint8_t *sk, uint8_t ss[HPKE_NSECRET]) {
    const uint8_t *ct_X = enc;
    const uint8_t *ct_M = enc + HPKE_X25519_ENCAPSULATED_BYTES;
    const uint8_t *sk_X = sk;
    const uint8_t *sk_M = sk + HPKE_X25519_SECRETKEY_BYTES;
    uint8_t pk_X[32], ss_X[32], ss_M[32];

    int rc = x25519_public_from_private(sk_X, pk_X);
    if (rc == PQ_SUCCESS) rc = x25519_dh(sk_X, ct_X, ss_X);
    if (rc == PQ_SUCCESS) rc = pq_kem_decapsulate(PQ_KEM_MLKEM768, ss_M, ct_M, sk_M);
    if (rc == PQ_SUCCESS)
        rc = pq_combiner_xwing_style(ss_M, sizeof(ss_M), ss_X, sizeof(ss_X),
                                     ct_X, 32, pk_X, 32,
                                     (const uint8_t *)PQ_XWING_LABEL, PQ_XWING_LABEL_BYTES,
                                     ss);
    OPENSSL_cleanse(ss_X, sizeof(ss_X));
    OPENSSL_cleanse(ss_M, sizeof(ss_M));
    return rc;
}

/* ========================================================================
 * KEM dispatch
 * ======================================================================== */

/* Encap; if ikmE != NULL the ephemeral key is DeriveKeyPair(ikmE) (X25519 only). */
static int kem_encap(int kem, const uint8_t *pk, uint8_t *enc, uint8_t ss[HPKE_NSECRET],
                     const uint8_t *ikmE, size_t ikmE_len) {
    int rc;

    if (ikmE && kem != HPKE_KEM_X25519)
        return PQ_ERR_UNSUPPORTED_ALGORITHM;

    switch (kem) {
        case HPKE_KEM_X25519: {
            uint8_t skE[32], pkE[32];
            rc = ikmE ? dhkem_x25519_derive_keypair(ikmE, ikmE_len, skE, pkE)
                      : x25519_generate(skE, pkE);
            if (rc == PQ_SUCCESS)
                rc = dhkem_x25519_encap_with(skE, pkE, pk, enc, ss);
            OPENSSL_cleanse(skE, sizeof(skE));
            break;
        }
        case HPKE_KEM_MLKEM768:
            rc = pq_kem_encapsulate(PQ_KEM_MLKEM768, enc, ss, pk);
            break;
        case HPKE_KEM_X25519_MLKEM768_CONCAT:
            rc = xwing_style_encap(pk, enc, ss);
            break;
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }

    if (rc != PQ_SUCCESS) {
        OPENSSL_cleanse(ss, HPKE_NSECRET);
        OPENSSL_cleanse(enc, pq_hpke_encapsulated_bytes(kem));
    }
    return rc;
}

static int kem_decap(int kem, const uint8_t *enc, const uint8_t *sk, uint8_t ss[HPKE_NSECRET]) {
    int rc;
    switch (kem) {
        case HPKE_KEM_X25519:
            rc = dhkem_x25519_decap(enc, sk, ss);
            break;
        case HPKE_KEM_MLKEM768:
            rc = pq_kem_decapsulate(PQ_KEM_MLKEM768, ss, enc, sk);
            break;
        case HPKE_KEM_X25519_MLKEM768_CONCAT:
            rc = xwing_style_decap(enc, sk, ss);
            break;
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(ss, HPKE_NSECRET);
    return rc;
}

/* ========================================================================
 * Key schedule (RFC 9180 section 5.1, mode_base, default PSK)
 * ======================================================================== */

static void wipe_key_schedule(pq_hpke_t *h) {
    OPENSSL_cleanse(h->key, sizeof(h->key));
    OPENSSL_cleanse(h->base_nonce, sizeof(h->base_nonce));
    OPENSSL_cleanse(h->exporter_secret, sizeof(h->exporter_secret));
    h->key_len = 0;
    h->seq = 0;
    h->role = HPKE_ROLE_NONE;
}

static int key_schedule(pq_hpke_t *h, int role,
                        const uint8_t ss[HPKE_NSECRET],
                        const uint8_t *info, size_t info_len) {
    uint8_t sid[HPKE_SUITE_ID_LEN];
    uint8_t ksc[1 + HPKE_NH + HPKE_NH];   /* mode || psk_id_hash || info_hash */
    uint8_t secret[HPKE_NH];
    size_t nk = aead_key_bytes(h->aead);
    int rc;

    if (nk == 0) return PQ_ERR_INVALID_ALGORITHM;
    hpke_suite_id(h, sid);

    ksc[0] = HPKE_MODE_BASE;
    /* psk_id = default_psk_id = "" ; psk = default_psk = "" */
    rc = labeled_extract(sid, sizeof(sid), NULL, 0, "psk_id_hash", NULL, 0, ksc + 1);
    if (rc == PQ_SUCCESS)
        rc = labeled_extract(sid, sizeof(sid), NULL, 0, "info_hash", info, info_len,
                             ksc + 1 + HPKE_NH);
    if (rc == PQ_SUCCESS)
        rc = labeled_extract(sid, sizeof(sid), ss, HPKE_NSECRET, "secret", NULL, 0, secret);
    if (rc == PQ_SUCCESS)
        rc = labeled_expand(sid, sizeof(sid), secret, "key", ksc, sizeof(ksc), h->key, nk);
    if (rc == PQ_SUCCESS)
        rc = labeled_expand(sid, sizeof(sid), secret, "base_nonce", ksc, sizeof(ksc),
                            h->base_nonce, HPKE_AEAD_NONCE_BYTES);
    if (rc == PQ_SUCCESS)
        rc = labeled_expand(sid, sizeof(sid), secret, "exp", ksc, sizeof(ksc),
                            h->exporter_secret, HPKE_NH);

    OPENSSL_cleanse(secret, sizeof(secret));
    if (rc != PQ_SUCCESS) {
        wipe_key_schedule(h);
        return rc;
    }
    h->key_len = nk;
    h->seq = 0;
    h->role = role;
    return PQ_SUCCESS;
}

/* nonce = base_nonce XOR I2OSP(seq, Nn); seq is 64-bit so only the last 8 bytes change */
static void compute_nonce(const pq_hpke_t *h, uint8_t nonce[HPKE_AEAD_NONCE_BYTES]) {
    memcpy(nonce, h->base_nonce, HPKE_AEAD_NONCE_BYTES);
    for (size_t i = 0; i < 8; i++)
        nonce[HPKE_AEAD_NONCE_BYTES - 1 - i] ^= (uint8_t)(h->seq >> (8 * i));
}

/* ========================================================================
 * Context management
 * ======================================================================== */

pq_hpke_t* pq_hpke_init(int kem, int aead) {
    if (pq_hpke_publickey_bytes(kem) == 0 || aead_key_bytes(aead) == 0)
        return NULL;

    pq_hpke_t *hpke = OPENSSL_zalloc(sizeof(*hpke));
    if (!hpke) return NULL;

    hpke->kem = kem;
    hpke->aead = aead;
    hpke->role = HPKE_ROLE_NONE;
    return hpke;
}

void pq_hpke_free(pq_hpke_t *hpke) {
    if (!hpke) return;
    OPENSSL_clear_free(hpke, sizeof(*hpke));
}

/* ========================================================================
 * KEM operations (public)
 * ======================================================================== */

int pq_hpke_keygen(pq_hpke_t *hpke, uint8_t *pk, size_t pk_len,
                   uint8_t *sk, size_t sk_len) {
    if (!hpke || !pk || !sk) return PQ_ERR_NULL_POINTER;

    size_t npk = pq_hpke_publickey_bytes(hpke->kem);
    size_t nsk = pq_hpke_secretkey_bytes(hpke->kem);
    if (npk == 0 || nsk == 0) return PQ_ERR_INVALID_ALGORITHM;
    if (pk_len < npk || sk_len < nsk) return PQ_ERR_BUFFER_TOO_SMALL;

    int rc;
    switch (hpke->kem) {
        case HPKE_KEM_X25519:
            rc = x25519_generate(sk, pk);
            break;
        case HPKE_KEM_MLKEM768:
            rc = pq_kem_keypair(PQ_KEM_MLKEM768, pk, sk);
            break;
        case HPKE_KEM_X25519_MLKEM768_CONCAT:
            rc = x25519_generate(sk, pk);
            if (rc == PQ_SUCCESS)
                rc = pq_kem_keypair(PQ_KEM_MLKEM768,
                                    pk + HPKE_X25519_PUBLICKEY_BYTES,
                                    sk + HPKE_X25519_SECRETKEY_BYTES);
            break;
        default:
            return PQ_ERR_INVALID_ALGORITHM;
    }

    if (rc != PQ_SUCCESS) {
        OPENSSL_cleanse(sk, nsk);
        OPENSSL_cleanse(pk, npk);
    }
    return rc;
}

int pq_hpke_derive_keypair(pq_hpke_t *hpke, const uint8_t *ikm, size_t ikm_len,
                           uint8_t *pk, size_t pk_len,
                           uint8_t *sk, size_t sk_len) {
    if (!hpke || !ikm || !pk || !sk) return PQ_ERR_NULL_POINTER;
    if (hpke->kem != HPKE_KEM_X25519) return PQ_ERR_UNSUPPORTED_ALGORITHM;
    if (pk_len < HPKE_X25519_PUBLICKEY_BYTES || sk_len < HPKE_X25519_SECRETKEY_BYTES)
        return PQ_ERR_BUFFER_TOO_SMALL;
    return dhkem_x25519_derive_keypair(ikm, ikm_len, sk, pk);
}

int pq_hpke_encapsulate(pq_hpke_t *hpke, uint8_t *enc, size_t enc_cap, size_t *enc_len,
                        uint8_t *ss, size_t ss_len,
                        const uint8_t *pk, size_t pk_len) {
    if (!hpke || !enc || !enc_len || !ss || !pk) return PQ_ERR_NULL_POINTER;

    size_t nenc = pq_hpke_encapsulated_bytes(hpke->kem);
    if (nenc == 0) return PQ_ERR_INVALID_ALGORITHM;
    if (pk_len != pq_hpke_publickey_bytes(hpke->kem)) return PQ_ERR_INVALID_PARAMETER;
    if (enc_cap < nenc || ss_len < HPKE_NSECRET) return PQ_ERR_BUFFER_TOO_SMALL;

    int rc = kem_encap(hpke->kem, pk, enc, ss, NULL, 0);
    if (rc == PQ_SUCCESS) *enc_len = nenc;
    return rc;
}

int pq_hpke_decapsulate(pq_hpke_t *hpke, uint8_t *ss, size_t ss_len,
                        const uint8_t *enc, size_t enc_len,
                        const uint8_t *sk, size_t sk_len) {
    if (!hpke || !ss || !enc || !sk) return PQ_ERR_NULL_POINTER;

    size_t nenc = pq_hpke_encapsulated_bytes(hpke->kem);
    if (nenc == 0) return PQ_ERR_INVALID_ALGORITHM;
    if (enc_len != nenc || sk_len != pq_hpke_secretkey_bytes(hpke->kem))
        return PQ_ERR_INVALID_PARAMETER;
    if (ss_len < HPKE_NSECRET) return PQ_ERR_BUFFER_TOO_SMALL;

    return kem_decap(hpke->kem, enc, sk, ss);
}

/* ========================================================================
 * Base-mode setup (public)
 * ======================================================================== */

static int setup_sender(pq_hpke_t *hpke,
                        const uint8_t *ikmE, size_t ikmE_len,
                        uint8_t *enc, size_t enc_cap, size_t *enc_len,
                        const uint8_t *pkR, size_t pkR_len,
                        const uint8_t *info, size_t info_len) {
    uint8_t ss[HPKE_NSECRET];

    if (!hpke || !enc || !enc_len || !pkR) return PQ_ERR_NULL_POINTER;
    if (info_len > 0 && !info) return PQ_ERR_NULL_POINTER;
    if (hpke->role != HPKE_ROLE_NONE) return PQ_ERR_INVALID_PARAMETER;

    size_t nenc = pq_hpke_encapsulated_bytes(hpke->kem);
    if (nenc == 0) return PQ_ERR_INVALID_ALGORITHM;
    if (pkR_len != pq_hpke_publickey_bytes(hpke->kem)) return PQ_ERR_INVALID_PARAMETER;
    if (enc_cap < nenc) return PQ_ERR_BUFFER_TOO_SMALL;

    int rc = kem_encap(hpke->kem, pkR, enc, ss, ikmE, ikmE_len);
    if (rc == PQ_SUCCESS)
        rc = key_schedule(hpke, HPKE_ROLE_SENDER, ss, info, info_len);
    OPENSSL_cleanse(ss, sizeof(ss));

    if (rc == PQ_SUCCESS)
        *enc_len = nenc;
    else
        OPENSSL_cleanse(enc, nenc);
    return rc;
}

int pq_hpke_setup_base_sender(pq_hpke_t *hpke,
                              uint8_t *enc, size_t enc_cap, size_t *enc_len,
                              const uint8_t *pkR, size_t pkR_len,
                              const uint8_t *info, size_t info_len) {
    return setup_sender(hpke, NULL, 0, enc, enc_cap, enc_len, pkR, pkR_len, info, info_len);
}

int pq_hpke_setup_base_sender_derand(pq_hpke_t *hpke,
                                     const uint8_t *ikmE, size_t ikmE_len,
                                     uint8_t *enc, size_t enc_cap, size_t *enc_len,
                                     const uint8_t *pkR, size_t pkR_len,
                                     const uint8_t *info, size_t info_len) {
    if (!ikmE) return PQ_ERR_NULL_POINTER;
    return setup_sender(hpke, ikmE, ikmE_len, enc, enc_cap, enc_len, pkR, pkR_len,
                        info, info_len);
}

int pq_hpke_setup_base_recipient(pq_hpke_t *hpke,
                                 const uint8_t *enc, size_t enc_len,
                                 const uint8_t *skR, size_t skR_len,
                                 const uint8_t *info, size_t info_len) {
    uint8_t ss[HPKE_NSECRET];

    if (!hpke || !enc || !skR) return PQ_ERR_NULL_POINTER;
    if (info_len > 0 && !info) return PQ_ERR_NULL_POINTER;
    if (hpke->role != HPKE_ROLE_NONE) return PQ_ERR_INVALID_PARAMETER;

    size_t nenc = pq_hpke_encapsulated_bytes(hpke->kem);
    if (nenc == 0) return PQ_ERR_INVALID_ALGORITHM;
    if (enc_len != nenc || skR_len != pq_hpke_secretkey_bytes(hpke->kem))
        return PQ_ERR_INVALID_PARAMETER;

    int rc = kem_decap(hpke->kem, enc, skR, ss);
    if (rc == PQ_SUCCESS)
        rc = key_schedule(hpke, HPKE_ROLE_RECIPIENT, ss, info, info_len);
    OPENSSL_cleanse(ss, sizeof(ss));
    return rc;
}

/* ========================================================================
 * AEAD (public)
 * ======================================================================== */

int pq_hpke_seal(pq_hpke_t *hpke, uint8_t *ct, size_t ct_cap, size_t *ct_len,
                 const uint8_t *pt, size_t pt_len,
                 const uint8_t *aad, size_t aad_len) {
    if (!hpke || !ct || !ct_len) return PQ_ERR_NULL_POINTER;
    if ((pt_len > 0 && !pt) || (aad_len > 0 && !aad)) return PQ_ERR_NULL_POINTER;
    if (hpke->role != HPKE_ROLE_SENDER) return PQ_ERR_INVALID_PARAMETER;
    if (pt_len > (size_t)INT_MAX - HPKE_AEAD_TAG_BYTES || aad_len > (size_t)INT_MAX)
        return PQ_ERR_INVALID_PARAMETER;
    if (ct_cap < pt_len + HPKE_AEAD_TAG_BYTES) return PQ_ERR_BUFFER_TOO_SMALL;
    if (hpke->seq == UINT64_MAX) return PQ_ERR_ENCRYPTION_FAILED;  /* MessageLimitReached */

    const EVP_CIPHER *cipher = aead_cipher(hpke->aead);
    if (!cipher) return PQ_ERR_INVALID_ALGORITHM;

    uint8_t nonce[HPKE_AEAD_NONCE_BYTES];
    int rc = PQ_ERR_ENCRYPTION_FAILED;
    int len = 0, fin_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return PQ_ERR_MEMORY_ALLOCATION;

    compute_nonce(hpke, nonce);

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, HPKE_AEAD_NONCE_BYTES, NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, hpke->key, nonce) != 1) goto done;
    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    len = 0;
    if (pt_len > 0 && EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &fin_len) != 1) goto done;
    if ((size_t)len + (size_t)fin_len != pt_len) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, HPKE_AEAD_TAG_BYTES, ct + pt_len) != 1)
        goto done;

    *ct_len = pt_len + HPKE_AEAD_TAG_BYTES;
    hpke->seq++;
    rc = PQ_SUCCESS;

done:
    if (rc != PQ_SUCCESS) OPENSSL_cleanse(ct, pt_len + HPKE_AEAD_TAG_BYTES);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return rc;
}

int pq_hpke_open(pq_hpke_t *hpke, uint8_t *pt, size_t pt_cap, size_t *pt_len,
                 const uint8_t *ct, size_t ct_len,
                 const uint8_t *aad, size_t aad_len) {
    if (!hpke || !pt_len || !ct) return PQ_ERR_NULL_POINTER;
    if (aad_len > 0 && !aad) return PQ_ERR_NULL_POINTER;
    if (hpke->role != HPKE_ROLE_RECIPIENT) return PQ_ERR_INVALID_PARAMETER;
    if (ct_len < HPKE_AEAD_TAG_BYTES) return PQ_ERR_INVALID_FORMAT;

    size_t body_len = ct_len - HPKE_AEAD_TAG_BYTES;
    if (body_len > (size_t)INT_MAX || aad_len > (size_t)INT_MAX)
        return PQ_ERR_INVALID_PARAMETER;
    if (body_len > 0 && !pt) return PQ_ERR_NULL_POINTER;
    if (pt_cap < body_len) return PQ_ERR_BUFFER_TOO_SMALL;
    if (hpke->seq == UINT64_MAX) return PQ_ERR_DECRYPTION_FAILED;  /* MessageLimitReached */

    const EVP_CIPHER *cipher = aead_cipher(hpke->aead);
    if (!cipher) return PQ_ERR_INVALID_ALGORITHM;

    uint8_t nonce[HPKE_AEAD_NONCE_BYTES];
    uint8_t tag[HPKE_AEAD_TAG_BYTES];
    uint8_t dummy[1];
    uint8_t *out = body_len > 0 ? pt : dummy;
    int rc = PQ_ERR_DECRYPTION_FAILED;
    int len = 0, fin_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return PQ_ERR_MEMORY_ALLOCATION;

    compute_nonce(hpke, nonce);
    memcpy(tag, ct + body_len, HPKE_AEAD_TAG_BYTES);

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, HPKE_AEAD_NONCE_BYTES, NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, hpke->key, nonce) != 1) goto done;
    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    len = 0;
    if (body_len > 0 && EVP_DecryptUpdate(ctx, out, &len, ct, (int)body_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, HPKE_AEAD_TAG_BYTES, tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out + len, &fin_len) != 1) {
        rc = PQ_ERR_VERIFICATION_FAILED;
        goto done;
    }
    if ((size_t)len + (size_t)fin_len != body_len) goto done;

    *pt_len = body_len;
    hpke->seq++;
    rc = PQ_SUCCESS;

done:
    /* Never release unauthenticated plaintext */
    if (rc != PQ_SUCCESS && body_len > 0) OPENSSL_cleanse(pt, body_len);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return rc;
}

int pq_hpke_export(pq_hpke_t *hpke,
                   const uint8_t *exporter_context, size_t exporter_context_len,
                   uint8_t *out, size_t out_len) {
    if (!hpke || !out) return PQ_ERR_NULL_POINTER;
    if (exporter_context_len > 0 && !exporter_context) return PQ_ERR_NULL_POINTER;
    if (hpke->role == HPKE_ROLE_NONE) return PQ_ERR_INVALID_PARAMETER;
    if (out_len == 0 || out_len > HPKE_EXPORT_MAX_BYTES) return PQ_ERR_INVALID_PARAMETER;

    uint8_t sid[HPKE_SUITE_ID_LEN];
    hpke_suite_id(hpke, sid);
    return labeled_expand(sid, sizeof(sid), hpke->exporter_secret, "sec",
                          exporter_context, exporter_context_len, out, out_len);
}
