/**
 * @file oqs_tls_integration.c
 * @brief OQS TLS Integration Implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 */

#include "oqs_tls_integration.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_OQS
#include <oqs/oqs.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct oqs_tls_context {
    oqs_tls_config_t config;
    bool initialized;
#ifdef HAVE_OQS
    OQS_KEM *kem;
    OQS_SIG *sig;
#endif
    void *ssl_ctx;  /* OpenSSL SSL_CTX */
};

/* Global initialization state */
static bool g_oqs_initialized = false;

/* ============================================================================
 * Algorithm Name Tables
 * ============================================================================ */

static const char *kem_names[] = {
    "None",
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "Kyber512",
    "Kyber768",
    "Kyber1024"
};

static const char *sig_names[] = {
    "None",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "Dilithium2",
    "Dilithium3",
    "Dilithium5",
    "SPHINCS+-SHA2-128f",
    "SPHINCS+-SHA2-192f",
    "SPHINCS+-SHA2-256f"
};

static const char *hybrid_group_strings[] = {
    "",
    "x25519_mlkem768",
    "p256_mlkem768",
    "p384_mlkem1024",
    "x25519_kyber768"
};

#ifdef HAVE_OQS
static const char *kem_oqs_names[] = {
    NULL,
    OQS_KEM_alg_ml_kem_512,
    OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024,
    OQS_KEM_alg_kyber_512,
    OQS_KEM_alg_kyber_768,
    OQS_KEM_alg_kyber_1024
};

static const char *sig_oqs_names[] = {
    NULL,
    OQS_SIG_alg_ml_dsa_44,
    OQS_SIG_alg_ml_dsa_65,
    OQS_SIG_alg_ml_dsa_87,
    OQS_SIG_alg_dilithium_2,
    OQS_SIG_alg_dilithium_3,
    OQS_SIG_alg_dilithium_5,
    OQS_SIG_alg_sphincs_sha2_128f_simple,
    OQS_SIG_alg_sphincs_sha2_192f_simple,
    OQS_SIG_alg_sphincs_sha2_256f_simple
};
#endif

/* ============================================================================
 * Timing Utilities
 * ============================================================================ */

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/* ============================================================================
 * Initialization and Cleanup
 * ============================================================================ */

int oqs_tls_init(void) {
    if (g_oqs_initialized) {
        return 0;
    }
    
#ifdef HAVE_OQS
    OQS_init();
#endif
    
    g_oqs_initialized = true;
    return 0;
}

void oqs_tls_cleanup(void) {
    if (!g_oqs_initialized) {
        return;
    }
    
#ifdef HAVE_OQS
    OQS_destroy();
#endif
    
    g_oqs_initialized = false;
}

bool oqs_tls_is_available(void) {
#ifdef HAVE_OQS
    return g_oqs_initialized;
#else
    return false;
#endif
}

/* ============================================================================
 * Context Management
 * ============================================================================ */

void oqs_tls_config_default(oqs_tls_config_t *config) {
    if (!config) return;
    
    memset(config, 0, sizeof(*config));
    config->kem_algorithm = OQS_KEM_ML_KEM_768;
    config->sig_algorithm = OQS_SIG_ML_DSA_65;
    config->hybrid_mode = OQS_HYBRID_X25519_MLKEM768;
    config->min_security_level = OQS_SECURITY_LEVEL_3;
    config->enable_hybrid = true;
    config->prefer_pq = true;
    config->allow_classical_fallback = true;
}

oqs_tls_context_t *oqs_tls_context_new(const oqs_tls_config_t *config) {
    if (!g_oqs_initialized) {
        if (oqs_tls_init() != 0) {
            return NULL;
        }
    }
    
    oqs_tls_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    
    if (config) {
        memcpy(&ctx->config, config, sizeof(*config));
    } else {
        oqs_tls_config_default(&ctx->config);
    }
    
#ifdef HAVE_OQS
    /* Initialize KEM if specified */
    if (ctx->config.kem_algorithm != OQS_KEM_NONE) {
        const char *kem_name = kem_oqs_names[ctx->config.kem_algorithm];
        if (kem_name && OQS_KEM_alg_is_enabled(kem_name)) {
            ctx->kem = OQS_KEM_new(kem_name);
        }
    }
    
    /* Initialize signature if specified */
    if (ctx->config.sig_algorithm != OQS_SIG_NONE) {
        const char *sig_name = sig_oqs_names[ctx->config.sig_algorithm];
        if (sig_name && OQS_SIG_alg_is_enabled(sig_name)) {
            ctx->sig = OQS_SIG_new(sig_name);
        }
    }
#endif
    
    ctx->initialized = true;
    return ctx;
}

void oqs_tls_context_free(oqs_tls_context_t *ctx) {
    if (!ctx) return;
    
#ifdef HAVE_OQS
    if (ctx->kem) {
        OQS_KEM_free(ctx->kem);
    }
    if (ctx->sig) {
        OQS_SIG_free(ctx->sig);
    }
#endif
    
    free(ctx);
}

/* ============================================================================
 * Algorithm Information
 * ============================================================================ */

const char *oqs_kem_algorithm_name(oqs_kem_algorithm_t alg) {
    if (alg >= OQS_KEM_COUNT) {
        return "Unknown";
    }
    return kem_names[alg];
}

const char *oqs_sig_algorithm_name(oqs_sig_algorithm_t alg) {
    if (alg >= OQS_SIG_COUNT) {
        return "Unknown";
    }
    return sig_names[alg];
}

oqs_security_level_t oqs_kem_security_level(oqs_kem_algorithm_t alg) {
    switch (alg) {
        case OQS_KEM_ML_KEM_512:
        case OQS_KEM_KYBER_512:
            return OQS_SECURITY_LEVEL_1;
        case OQS_KEM_ML_KEM_768:
        case OQS_KEM_KYBER_768:
            return OQS_SECURITY_LEVEL_3;
        case OQS_KEM_ML_KEM_1024:
        case OQS_KEM_KYBER_1024:
            return OQS_SECURITY_LEVEL_5;
        default:
            return OQS_SECURITY_LEVEL_1;
    }
}

oqs_security_level_t oqs_sig_security_level(oqs_sig_algorithm_t alg) {
    switch (alg) {
        case OQS_SIG_ML_DSA_44:
        case OQS_SIG_DILITHIUM_2:
        case OQS_SIG_SPHINCS_SHA2_128F:
            return OQS_SECURITY_LEVEL_1;
        case OQS_SIG_ML_DSA_65:
        case OQS_SIG_DILITHIUM_3:
        case OQS_SIG_SPHINCS_SHA2_192F:
            return OQS_SECURITY_LEVEL_3;
        case OQS_SIG_ML_DSA_87:
        case OQS_SIG_DILITHIUM_5:
        case OQS_SIG_SPHINCS_SHA2_256F:
            return OQS_SECURITY_LEVEL_5;
        default:
            return OQS_SECURITY_LEVEL_1;
    }
}

bool oqs_kem_is_available(oqs_kem_algorithm_t alg) {
#ifdef HAVE_OQS
    if (alg == OQS_KEM_NONE || alg >= OQS_KEM_COUNT) {
        return false;
    }
    const char *name = kem_oqs_names[alg];
    return name && OQS_KEM_alg_is_enabled(name);
#else
    return false;
#endif
}

bool oqs_sig_is_available(oqs_sig_algorithm_t alg) {
#ifdef HAVE_OQS
    if (alg == OQS_SIG_NONE || alg >= OQS_SIG_COUNT) {
        return false;
    }
    const char *name = sig_oqs_names[alg];
    return name && OQS_SIG_alg_is_enabled(name);
#else
    return false;
#endif
}

/* ============================================================================
 * Benchmarking
 * ============================================================================ */

int oqs_kem_benchmark(oqs_kem_algorithm_t alg, int iterations,
                      oqs_algorithm_metrics_t *metrics) {
    if (!metrics || alg == OQS_KEM_NONE || alg >= OQS_KEM_COUNT) {
        return -1;
    }
    
    memset(metrics, 0, sizeof(*metrics));
    
#ifdef HAVE_OQS
    const char *name = kem_oqs_names[alg];
    if (!name || !OQS_KEM_alg_is_enabled(name)) {
        return -2;
    }
    
    OQS_KEM *kem = OQS_KEM_new(name);
    if (!kem) {
        return -3;
    }
    
    metrics->public_key_size = kem->length_public_key;
    metrics->secret_key_size = kem->length_secret_key;
    metrics->ciphertext_size = kem->length_ciphertext;
    metrics->shared_secret_size = kem->length_shared_secret;
    
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_e = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_d = malloc(kem->length_shared_secret);
    
    if (!public_key || !secret_key || !ciphertext || 
        !shared_secret_e || !shared_secret_d) {
        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(shared_secret_e);
        free(shared_secret_d);
        OQS_KEM_free(kem);
        return -4;
    }
    
    double start, total_keygen = 0, total_encaps = 0, total_decaps = 0;
    
    for (int i = 0; i < iterations; i++) {
        start = get_time_ms();
        OQS_KEM_keypair(kem, public_key, secret_key);
        total_keygen += get_time_ms() - start;
        
        start = get_time_ms();
        OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
        total_encaps += get_time_ms() - start;
        
        start = get_time_ms();
        OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
        total_decaps += get_time_ms() - start;
    }
    
    metrics->keygen_time_ms = total_keygen / iterations;
    metrics->encaps_time_ms = total_encaps / iterations;
    metrics->decaps_time_ms = total_decaps / iterations;
    
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_e);
    free(shared_secret_d);
    OQS_KEM_free(kem);
    
    return 0;
#else
    /* Simulated benchmarks when OQS not available */
    switch (alg) {
        case OQS_KEM_ML_KEM_512:
            metrics->keygen_time_ms = 0.045;
            metrics->encaps_time_ms = 0.055;
            metrics->decaps_time_ms = 0.060;
            metrics->public_key_size = 800;
            metrics->secret_key_size = 1632;
            metrics->ciphertext_size = 768;
            metrics->shared_secret_size = 32;
            break;
        case OQS_KEM_ML_KEM_768:
            metrics->keygen_time_ms = 0.075;
            metrics->encaps_time_ms = 0.090;
            metrics->decaps_time_ms = 0.095;
            metrics->public_key_size = 1184;
            metrics->secret_key_size = 2400;
            metrics->ciphertext_size = 1088;
            metrics->shared_secret_size = 32;
            break;
        case OQS_KEM_ML_KEM_1024:
            metrics->keygen_time_ms = 0.120;
            metrics->encaps_time_ms = 0.140;
            metrics->decaps_time_ms = 0.150;
            metrics->public_key_size = 1568;
            metrics->secret_key_size = 3168;
            metrics->ciphertext_size = 1568;
            metrics->shared_secret_size = 32;
            break;
        default:
            return -2;
    }
    return 0;
#endif
}

int oqs_sig_benchmark(oqs_sig_algorithm_t alg, int iterations,
                      oqs_algorithm_metrics_t *metrics) {
    if (!metrics || alg == OQS_SIG_NONE || alg >= OQS_SIG_COUNT) {
        return -1;
    }
    
    memset(metrics, 0, sizeof(*metrics));
    
#ifdef HAVE_OQS
    const char *name = sig_oqs_names[alg];
    if (!name || !OQS_SIG_alg_is_enabled(name)) {
        return -2;
    }
    
    OQS_SIG *sig = OQS_SIG_new(name);
    if (!sig) {
        return -3;
    }
    
    metrics->public_key_size = sig->length_public_key;
    metrics->secret_key_size = sig->length_secret_key;
    metrics->ciphertext_size = sig->length_signature;
    
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t message[] = "Test message for benchmarking PQ signatures";
    size_t sig_len;
    
    if (!public_key || !secret_key || !signature) {
        free(public_key);
        free(secret_key);
        free(signature);
        OQS_SIG_free(sig);
        return -4;
    }
    
    double start, total_keygen = 0, total_sign = 0, total_verify = 0;
    
    for (int i = 0; i < iterations; i++) {
        start = get_time_ms();
        OQS_SIG_keypair(sig, public_key, secret_key);
        total_keygen += get_time_ms() - start;
        
        start = get_time_ms();
        OQS_SIG_sign(sig, signature, &sig_len, message, sizeof(message), secret_key);
        total_sign += get_time_ms() - start;
        
        start = get_time_ms();
        OQS_SIG_verify(sig, message, sizeof(message), signature, sig_len, public_key);
        total_verify += get_time_ms() - start;
    }
    
    metrics->keygen_time_ms = total_keygen / iterations;
    metrics->sign_time_ms = total_sign / iterations;
    metrics->verify_time_ms = total_verify / iterations;
    
    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);
    
    return 0;
#else
    /* Simulated benchmarks */
    switch (alg) {
        case OQS_SIG_ML_DSA_44:
            metrics->keygen_time_ms = 0.15;
            metrics->sign_time_ms = 0.35;
            metrics->verify_time_ms = 0.12;
            metrics->public_key_size = 1312;
            metrics->secret_key_size = 2560;
            metrics->ciphertext_size = 2420;
            break;
        case OQS_SIG_ML_DSA_65:
            metrics->keygen_time_ms = 0.25;
            metrics->sign_time_ms = 0.55;
            metrics->verify_time_ms = 0.18;
            metrics->public_key_size = 1952;
            metrics->secret_key_size = 4032;
            metrics->ciphertext_size = 3309;
            break;
        case OQS_SIG_ML_DSA_87:
            metrics->keygen_time_ms = 0.40;
            metrics->sign_time_ms = 0.85;
            metrics->verify_time_ms = 0.28;
            metrics->public_key_size = 2592;
            metrics->secret_key_size = 4896;
            metrics->ciphertext_size = 4627;
            break;
        default:
            return -2;
    }
    return 0;
#endif
}

/* ============================================================================
 * TLS Integration
 * ============================================================================ */

const char *oqs_hybrid_group_string(oqs_hybrid_mode_t mode) {
    if (mode >= OQS_HYBRID_COUNT) {
        return "";
    }
    return hybrid_group_strings[mode];
}

int oqs_create_groups_string(const oqs_hybrid_mode_t *modes, size_t count,
                             char *buffer, size_t buffer_size) {
    if (!modes || !buffer || buffer_size == 0) {
        return -1;
    }
    
    buffer[0] = '\0';
    size_t offset = 0;
    
    for (size_t i = 0; i < count; i++) {
        const char *group = oqs_hybrid_group_string(modes[i]);
        if (!group || group[0] == '\0') {
            continue;
        }
        
        size_t len = strlen(group);
        if (offset + len + 2 > buffer_size) {
            return -2;  /* Buffer too small */
        }
        
        if (offset > 0) {
            buffer[offset++] = ':';
        }
        memcpy(buffer + offset, group, len);
        offset += len;
    }
    
    buffer[offset] = '\0';
    return (int)offset;
}

int oqs_tls_configure_ssl_ctx(oqs_tls_context_t *ctx, void *ssl_ctx) {
    if (!ctx || !ssl_ctx) {
        return -1;
    }
    
#ifdef HAVE_OPENSSL
    SSL_CTX *sctx = (SSL_CTX *)ssl_ctx;
    
    /* Set minimum TLS version to 1.3 for PQ support */
    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
    
    /* Configure hybrid groups if enabled */
    if (ctx->config.enable_hybrid && ctx->config.hybrid_mode != OQS_HYBRID_NONE) {
        const char *groups = oqs_hybrid_group_string(ctx->config.hybrid_mode);
        if (groups && groups[0] != '\0') {
            /* Add classical fallback groups */
            char group_list[256];
            snprintf(group_list, sizeof(group_list), "%s:X25519:P-256:P-384", groups);
            SSL_CTX_set1_groups_list(sctx, group_list);
        }
    }
    
    ctx->ssl_ctx = ssl_ctx;
    return 0;
#else
    return -2;  /* OpenSSL not available */
#endif
}
