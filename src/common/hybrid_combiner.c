/**
 * @file hybrid_combiner.c
 * @brief Hybrid Combiner Implementations
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements KDF-Concat and XOR combiners for merging classical
 * and post-quantum shared secrets into a single hybrid secret.
 */

#include "hybrid_combiner.h"
#include "pq_errors.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 * KDF-Concat Combiner (IETF Hybrid Draft aligned)
 *
 * SS = HKDF-SHA256(salt="", ikm=classical_ss || pq_ss, info=context, L=32)
 * ======================================================================== */

#define KDF_CONCAT_OUTPUT_SIZE 32

static int kdf_concat_combine(const uint8_t *classical_ss, size_t classical_ss_len,
                               const uint8_t *pq_ss, size_t pq_ss_len,
                               uint8_t *out, size_t *out_len,
                               const uint8_t *context, size_t context_len)
{
    if (!classical_ss || !pq_ss || !out || !out_len)
        return PQ_ERR_NULL_POINTER;
    if (*out_len < KDF_CONCAT_OUTPUT_SIZE)
        return PQ_ERR_BUFFER_TOO_SMALL;

    /* Build IKM = classical_ss || pq_ss */
    size_t ikm_len = classical_ss_len + pq_ss_len;
    uint8_t *ikm = malloc(ikm_len);
    if (!ikm) return PQ_ERR_MEMORY_ALLOCATION;

    memcpy(ikm, classical_ss, classical_ss_len);
    memcpy(ikm + classical_ss_len, pq_ss, pq_ss_len);

    /* Default context for domain separation */
    const uint8_t default_ctx[] = "pq-tls-hybrid-v1";
    if (!context || context_len == 0) {
        context = default_ctx;
        context_len = sizeof(default_ctx) - 1;
    }

    int rc = PQ_ERR_CRYPTO_FAILED;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto done;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) goto done;

    OSSL_PARAM params[5];
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    params[0] = OSSL_PARAM_construct_int("mode", &mode);
    params[1] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[2] = OSSL_PARAM_construct_octet_string("key", (void *)ikm, ikm_len);
    params[3] = OSSL_PARAM_construct_octet_string("info", (void *)context, context_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, KDF_CONCAT_OUTPUT_SIZE, params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        goto done;
    }

    EVP_KDF_CTX_free(kctx);
    *out_len = KDF_CONCAT_OUTPUT_SIZE;
    rc = PQ_SUCCESS;

done:
    OPENSSL_cleanse(ikm, ikm_len);
    free(ikm);
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
 * XOR Combiner
 *
 * SS = classical_ss XOR pq_ss (both must be 32 bytes)
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
    .name        = "XOR",
    .combine     = xor_combine,
    .output_size = xor_output_size,
};

const pq_hybrid_combiner_t *pq_combiner_xor(void)
{
    return &xor_combiner;
}
