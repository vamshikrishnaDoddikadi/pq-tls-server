/**
 * @file hybrid_combiner.c
 * @brief Hybrid Combiner Implementations
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements the KDF-Concat and (deprecated) XOR combiners for merging
 * classical and post-quantum shared secrets, plus the X-Wing-style SHA3-256
 * combiner and the transcript-binding helper.  See hybrid_combiner.h for the
 * security discussion.
 */

#include "hybrid_combiner.h"
#include "pq_errors.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * Internal helpers
 * ======================================================================== */

typedef struct {
    const uint8_t *p;
    size_t n;
} comb_iov_t;

/** SHA3-256 over a list of buffers. */
static int sha3_256_iov(const comb_iov_t *iov, size_t n_iov, uint8_t out[32])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    int rc = PQ_ERR_CRYPTO_FAILED;

    if (!md) return PQ_ERR_MEMORY_ALLOCATION;
    if (EVP_DigestInit_ex(md, EVP_sha3_256(), NULL) != 1) goto done;
    for (size_t i = 0; i < n_iov; i++) {
        if (iov[i].n == 0) continue;
        if (!iov[i].p) { rc = PQ_ERR_NULL_POINTER; goto done; }
        if (EVP_DigestUpdate(md, iov[i].p, iov[i].n) != 1) goto done;
    }
    if (EVP_DigestFinal_ex(md, out, &out_len) != 1 || out_len != 32) goto done;
    rc = PQ_SUCCESS;

done:
    EVP_MD_CTX_free(md);
    return rc;
}

static void put_u32_be(uint8_t out[4], size_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

/* ========================================================================
 * X-Wing-style combiner
 * ======================================================================== */

int pq_combiner_xwing_style(const uint8_t *ss_pq, size_t ss_pq_len,
                            const uint8_t *ss_t, size_t ss_t_len,
                            const uint8_t *ct_t, size_t ct_t_len,
                            const uint8_t *pk_t, size_t pk_t_len,
                            const uint8_t *label, size_t label_len,
                            uint8_t out[PQ_COMBINER_XWING_SS_BYTES])
{
    if (!ss_pq || !ss_t || !ct_t || !pk_t || !out)
        return PQ_ERR_NULL_POINTER;
    if (ss_pq_len == 0 || ss_t_len == 0 || ct_t_len == 0 || pk_t_len == 0 ||
        label_len == 0 || !label)
        return PQ_ERR_INVALID_PARAMETER;

    const comb_iov_t iov[] = {
        { ss_pq, ss_pq_len },
        { ss_t,  ss_t_len  },
        { ct_t,  ct_t_len  },
        { pk_t,  pk_t_len  },
        { label, label_len },
    };
    int rc = sha3_256_iov(iov, sizeof(iov) / sizeof(iov[0]), out);
    if (rc != PQ_SUCCESS)
        OPENSSL_cleanse(out, PQ_COMBINER_XWING_SS_BYTES);
    return rc;
}

/* ========================================================================
 * Transcript binding helper
 * ======================================================================== */

int pq_combiner_transcript_hash(const uint8_t *ct_c, size_t ct_c_len,
                                const uint8_t *ct_pq, size_t ct_pq_len,
                                const uint8_t *pk_c, size_t pk_c_len,
                                const uint8_t *pk_pq, size_t pk_pq_len,
                                uint8_t out[PQ_COMBINER_TRANSCRIPT_HASH_BYTES])
{
    static const char label[] = "pq-tls-kem-transcript-v1";
    uint8_t l_ct_c[4], l_ct_pq[4], l_pk_c[4], l_pk_pq[4];

    if (!out) return PQ_ERR_NULL_POINTER;
    if ((ct_c_len && !ct_c) || (ct_pq_len && !ct_pq) ||
        (pk_c_len && !pk_c) || (pk_pq_len && !pk_pq))
        return PQ_ERR_NULL_POINTER;
    if (ct_c_len > UINT32_MAX || ct_pq_len > UINT32_MAX ||
        pk_c_len > UINT32_MAX || pk_pq_len > UINT32_MAX)
        return PQ_ERR_INVALID_PARAMETER;

    put_u32_be(l_ct_c, ct_c_len);
    put_u32_be(l_ct_pq, ct_pq_len);
    put_u32_be(l_pk_c, pk_c_len);
    put_u32_be(l_pk_pq, pk_pq_len);

    const comb_iov_t iov[] = {
        { (const uint8_t *)label, sizeof(label) - 1 },
        { l_ct_c, 4 },  { ct_c, ct_c_len },
        { l_ct_pq, 4 }, { ct_pq, ct_pq_len },
        { l_pk_c, 4 },  { pk_c, pk_c_len },
        { l_pk_pq, 4 }, { pk_pq, pk_pq_len },
    };
    return sha3_256_iov(iov, sizeof(iov) / sizeof(iov[0]), out);
}

/* ========================================================================
 * KDF-Concat Combiner
 *
 * out = HKDF-SHA256(salt = "",
 *                   ikm  = I2OSP(|c_ss|,2) || c_ss || I2OSP(|pq_ss|,2) || pq_ss,
 *                   info = "pq-tls-kdf-concat-v2" || context,
 *                   L    = 32)
 *
 * The explicit length framing makes the IKM encoding injective even though
 * the interface accepts variable-length shared secrets.
 * ======================================================================== */

#define KDF_CONCAT_OUTPUT_SIZE 32
#define KDF_CONCAT_MAX_SS      0xFFFFu

static int kdf_concat_combine(const uint8_t *classical_ss, size_t classical_ss_len,
                               const uint8_t *pq_ss, size_t pq_ss_len,
                               uint8_t *out, size_t *out_len,
                               const uint8_t *context, size_t context_len)
{
    static const uint8_t info_label[] = "pq-tls-kdf-concat-v2";
    static const uint8_t default_ctx[] = "pq-tls-hybrid-v1";

    if (!classical_ss || !pq_ss || !out || !out_len)
        return PQ_ERR_NULL_POINTER;
    if (classical_ss_len == 0 || pq_ss_len == 0 ||
        classical_ss_len > KDF_CONCAT_MAX_SS || pq_ss_len > KDF_CONCAT_MAX_SS)
        return PQ_ERR_INVALID_PARAMETER;
    if (*out_len < KDF_CONCAT_OUTPUT_SIZE)
        return PQ_ERR_BUFFER_TOO_SMALL;
    if (context_len > 0 && !context)
        return PQ_ERR_NULL_POINTER;

    if (context_len == 0) {
        context = default_ctx;
        context_len = sizeof(default_ctx) - 1;
    }

    const size_t info_label_len = sizeof(info_label) - 1;
    if (context_len > SIZE_MAX - info_label_len)
        return PQ_ERR_INVALID_PARAMETER;

    /* IKM = I2OSP(len,2) || classical_ss || I2OSP(len,2) || pq_ss */
    size_t ikm_len = 2 + classical_ss_len + 2 + pq_ss_len;
    size_t info_len = info_label_len + context_len;
    uint8_t *ikm = OPENSSL_malloc(ikm_len);
    uint8_t *info = OPENSSL_malloc(info_len);
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    int rc = PQ_ERR_CRYPTO_FAILED;

    if (!ikm || !info) {
        rc = PQ_ERR_MEMORY_ALLOCATION;
        goto done;
    }

    size_t off = 0;
    ikm[off++] = (uint8_t)(classical_ss_len >> 8);
    ikm[off++] = (uint8_t)classical_ss_len;
    memcpy(ikm + off, classical_ss, classical_ss_len);
    off += classical_ss_len;
    ikm[off++] = (uint8_t)(pq_ss_len >> 8);
    ikm[off++] = (uint8_t)pq_ss_len;
    memcpy(ikm + off, pq_ss, pq_ss_len);

    memcpy(info, info_label, info_label_len);
    memcpy(info + info_label_len, context, context_len);

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto done;
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) goto done;

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len),
        OSSL_PARAM_construct_end(),
    };

    if (EVP_KDF_derive(kctx, out, KDF_CONCAT_OUTPUT_SIZE, params) <= 0) {
        OPENSSL_cleanse(out, KDF_CONCAT_OUTPUT_SIZE);
        goto done;
    }

    *out_len = KDF_CONCAT_OUTPUT_SIZE;
    rc = PQ_SUCCESS;

done:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OPENSSL_clear_free(ikm, ikm_len);
    OPENSSL_free(info);
    return rc;
}

static size_t kdf_concat_output_size(size_t classical_ss_len, size_t pq_ss_len)
{
    (void)classical_ss_len;
    (void)pq_ss_len;
    return KDF_CONCAT_OUTPUT_SIZE;
}

static const pq_hybrid_combiner_t kdf_concat_combiner = {
    .method      = PQ_COMBINER_KDF_CONCAT,
    .name        = "KDF-Concat (HKDF-SHA256)",
    .combine     = kdf_concat_combine,
    .output_size = kdf_concat_output_size,
};

const pq_hybrid_combiner_t *pq_combiner_kdf_concat(void)
{
    return &kdf_concat_combiner;
}

/* ========================================================================
 * XOR Combiner - DEPRECATED / INSECURE
 *
 * SS = classical_ss XOR pq_ss (both must be 32 bytes).
 *
 * Not an IND-CCA KEM combiner (see hybrid_combiner.h).  Retained only so the
 * registry can still look it up by PQ_COMBINER_XOR; no built-in hybrid pair
 * uses it.
 * ======================================================================== */

static int xor_combine(const uint8_t *classical_ss, size_t classical_ss_len,
                        const uint8_t *pq_ss, size_t pq_ss_len,
                        uint8_t *out, size_t *out_len,
                        const uint8_t *context, size_t context_len)
{
    (void)context;
    (void)context_len;

    if (!classical_ss || !pq_ss || !out || !out_len)
        return PQ_ERR_NULL_POINTER;
    if (classical_ss_len != 32 || pq_ss_len != 32)
        return PQ_ERR_INVALID_PARAMETER;
    if (*out_len < 32)
        return PQ_ERR_BUFFER_TOO_SMALL;

    for (size_t i = 0; i < 32; i++)
        out[i] = classical_ss[i] ^ pq_ss[i];

    *out_len = 32;
    return PQ_SUCCESS;
}

static size_t xor_output_size(size_t classical_ss_len, size_t pq_ss_len)
{
    (void)classical_ss_len;
    (void)pq_ss_len;
    return 32;
}

static const pq_hybrid_combiner_t xor_combiner = {
    .method      = PQ_COMBINER_XOR,
    .name        = "XOR (deprecated, insecure)",
    .combine     = xor_combine,
    .output_size = xor_output_size,
};

const pq_hybrid_combiner_t *pq_combiner_xor(void)
{
    return &xor_combiner;
}
