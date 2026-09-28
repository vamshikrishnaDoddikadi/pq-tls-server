/**
 * @file bench_agility.c
 * @brief ML-KEM Hybrid Benchmark Suite — Implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 */

#include "bench_agility.h"
#include "../common/hybrid_combiner.h"
#include "../common/pq_errors.h"

#include <openssl/crypto.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#ifndef _WIN32
#include <sched.h>
#endif

/* ========================================================================
 * Timing Helpers
 * ======================================================================== */

static inline uint64_t clock_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ========================================================================
 * Statistics Helpers
 * ======================================================================== */

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static void compute_stats(double *samples, size_t count, pq_bench_stats_t *out)
{
    if (count == 0) { memset(out, 0, sizeof(*out)); return; }

    qsort(samples, count, sizeof(double), cmp_double);

    out->min_us = samples[0];
    out->max_us = samples[count - 1];
    out->median_us = samples[count / 2];
    out->p95_us = samples[(size_t)(count * 0.95)];
    out->p99_us = samples[(size_t)(count * 0.99)];
    out->samples = count;

    double sum = 0;
    for (size_t i = 0; i < count; i++) sum += samples[i];
    out->mean_us = sum / (double)count;

    double var = 0;
    for (size_t i = 0; i < count; i++) {
        double d = samples[i] - out->mean_us;
        var += d * d;
    }
    out->stddev_us = sqrt(var / (double)count);

    /* 95% CI: mean +/- 1.96 * stddev / sqrt(n) */
    double margin = 1.96 * out->stddev_us / sqrt((double)count);
    out->ci95_low  = out->mean_us - margin;
    out->ci95_high = out->mean_us + margin;
}

/* ========================================================================
 * CPU Pinning
 * ======================================================================== */

static void pin_cpu(int core)
{
#ifndef _WIN32
    if (core < 0) return;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core, &set);
    sched_setaffinity(0, sizeof(set), &set);
#else
    (void)core;
#endif
}

/* ========================================================================
 * Default Config
 * ======================================================================== */

void pq_bench_config_default(pq_bench_config_t *cfg)
{
    if (!cfg) return;
    cfg->iterations       = 1000;
    cfg->warmup_iterations = 100;
    cfg->cpu_pin          = -1;
    cfg->disable_turbo    = 0;
    cfg->verbose          = 0;
}

/* ========================================================================
 * Common helpers
 *
 * Every benchmark checks every operation's return value and ABORTS on the
 * first failure (returning the error) instead of silently skipping or
 * timing an error path.  KEM runs also verify that encapsulation and
 * decapsulation agree; signature runs verify every signature.
 * ======================================================================== */

static int bench_cfg_valid(const pq_bench_config_t *cfg)
{
    return cfg->iterations > 0 && cfg->warmup_iterations >= 0 &&
           cfg->warmup_iterations <= INT32_MAX - cfg->iterations;
}

static void secure_free(uint8_t *p, size_t len)
{
    if (p) OPENSSL_cleanse(p, len);
    free(p);
}

static int bench_fail(const char *what, const char *alg, int iteration, int rc)
{
    fprintf(stderr, "[bench] %s: %s failed at iteration %d: %s\n",
            alg, what, iteration, pq_error_string(rc));
    return rc;
}

/* ========================================================================
 * KEM Benchmark
 * ======================================================================== */

int pq_bench_kem(const pq_kem_provider_t *provider,
                  const pq_bench_config_t *cfg,
                  pq_kem_bench_result_t *result)
{
    if (!provider || !cfg || !result) return PQ_ERR_INVALID_PARAMETER;
    if (!bench_cfg_valid(cfg)) return PQ_ERR_INVALID_PARAMETER;
    if (!provider->is_available()) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    const pq_algorithm_metadata_t *m = provider->metadata();
    if (!m || !m->pk_size || !m->sk_size || !m->ct_size || !m->ss_size)
        return PQ_ERR_INVALID_PARAMETER;

    memset(result, 0, sizeof(*result));
    result->algorithm_name = m->name;
    result->nist_level = m->nist_level;
    result->family = m->family;
    result->pk_bytes = m->pk_size;
    result->sk_bytes = m->sk_size;
    result->ct_bytes = m->ct_size;
    result->ss_bytes = m->ss_size;
    result->total_handshake_bytes = m->pk_size + m->ct_size;

    pin_cpu(cfg->cpu_pin);

    int total = cfg->warmup_iterations + cfg->iterations;
    int rc = PQ_ERR_MEMORY_ALLOCATION;
    double *keygen_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    double *encaps_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    double *decaps_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    /* Buffers are sized from the provider metadata (for HQC these are the
     * runtime sizes reported by liboqs). */
    uint8_t *pk = malloc(m->pk_size);
    uint8_t *sk = malloc(m->sk_size);
    uint8_t *ct = malloc(m->ct_size);
    uint8_t *ss1 = malloc(m->ss_size);
    uint8_t *ss2 = malloc(m->ss_size);
    if (!keygen_times || !encaps_times || !decaps_times ||
        !pk || !sk || !ct || !ss1 || !ss2)
        goto done;

    int sample_idx = 0;
    for (int i = 0; i < total; i++) {
        bool warmup = (i < cfg->warmup_iterations);

        /* Keygen */
        uint64_t t0 = clock_ns();
        rc = provider->keygen(pk, sk);
        uint64_t t1 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("keygen", m->name, i, rc); goto done; }

        /* Encapsulate */
        uint64_t t2 = clock_ns();
        rc = provider->encapsulate(pk, ct, ss1);
        uint64_t t3 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("encapsulate", m->name, i, rc); goto done; }

        /* Decapsulate */
        uint64_t t4 = clock_ns();
        rc = provider->decapsulate(sk, ct, ss2);
        uint64_t t5 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("decapsulate", m->name, i, rc); goto done; }

        /* Correctness */
        if (CRYPTO_memcmp(ss1, ss2, m->ss_size) != 0) {
            rc = bench_fail("shared-secret check", m->name, i, PQ_ERR_CRYPTO_FAILED);
            goto done;
        }

        if (!warmup && sample_idx < cfg->iterations) {
            keygen_times[sample_idx] = (double)(t1 - t0) / 1000.0; /* ns -> us */
            encaps_times[sample_idx] = (double)(t3 - t2) / 1000.0;
            decaps_times[sample_idx] = (double)(t5 - t4) / 1000.0;
            sample_idx++;
        }
    }

    compute_stats(keygen_times, (size_t)sample_idx, &result->keygen);
    compute_stats(encaps_times, (size_t)sample_idx, &result->encapsulate);
    compute_stats(decaps_times, (size_t)sample_idx, &result->decapsulate);
    rc = PQ_SUCCESS;

done:
    free(pk); secure_free(sk, m->sk_size); free(ct);
    secure_free(ss1, m->ss_size); secure_free(ss2, m->ss_size);
    free(keygen_times); free(encaps_times); free(decaps_times);
    return rc;
}

/* ========================================================================
 * SIG Benchmark
 * ======================================================================== */

int pq_bench_sig(const pq_sig_provider_t *provider,
                  const pq_bench_config_t *cfg,
                  pq_sig_bench_result_t *result)
{
    if (!provider || !cfg || !result) return PQ_ERR_INVALID_PARAMETER;
    if (!bench_cfg_valid(cfg)) return PQ_ERR_INVALID_PARAMETER;
    if (!provider->is_available()) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    const pq_algorithm_metadata_t *m = provider->metadata();
    if (!m || !m->pk_size || !m->sk_size || !m->ct_size) return PQ_ERR_INVALID_PARAMETER;

    memset(result, 0, sizeof(*result));
    result->algorithm_name = m->name;
    result->nist_level = m->nist_level;
    result->pk_bytes = m->pk_size;
    result->sig_bytes = m->ct_size;

    pin_cpu(cfg->cpu_pin);

    int total = cfg->warmup_iterations + cfg->iterations;
    int rc = PQ_ERR_MEMORY_ALLOCATION;
    double *keygen_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    double *sign_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    double *verify_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    uint8_t *pk = malloc(m->pk_size);
    uint8_t *sk = malloc(m->sk_size);
    uint8_t *sig = malloc(m->ct_size);   /* ct_size = max signature size */
    if (!keygen_times || !sign_times || !verify_times || !pk || !sk || !sig)
        goto done;

    const uint8_t msg[] = "benchmark test message for PQ digital signatures";
    size_t msg_len = sizeof(msg) - 1;

    int sample_idx = 0;
    for (int i = 0; i < total; i++) {
        bool warmup = (i < cfg->warmup_iterations);

        uint64_t t0 = clock_ns();
        rc = provider->keygen(pk, sk);
        uint64_t t1 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("keygen", m->name, i, rc); goto done; }

        /* Reset to the buffer capacity before EVERY sign: it is overwritten
         * with the signature length (a stale/zero value makes OpenSSL-backed
         * signers such as Ed25519 fail). */
        size_t sig_len = m->ct_size;
        uint64_t t2 = clock_ns();
        rc = provider->sign(sk, msg, msg_len, sig, &sig_len);
        uint64_t t3 = clock_ns();
        if (rc == PQ_SUCCESS && (sig_len == 0 || sig_len > m->ct_size))
            rc = PQ_ERR_SIGNATURE_FAILED;
        if (rc != PQ_SUCCESS) { bench_fail("sign", m->name, i, rc); goto done; }

        uint64_t t4 = clock_ns();
        rc = provider->verify(pk, msg, msg_len, sig, sig_len);
        uint64_t t5 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("verify", m->name, i, rc); goto done; }

        if (!warmup && sample_idx < cfg->iterations) {
            keygen_times[sample_idx] = (double)(t1 - t0) / 1000.0;
            sign_times[sample_idx]   = (double)(t3 - t2) / 1000.0;
            verify_times[sample_idx] = (double)(t5 - t4) / 1000.0;
            sample_idx++;
        }
    }

    compute_stats(keygen_times, (size_t)sample_idx, &result->keygen);
    compute_stats(sign_times, (size_t)sample_idx, &result->sign);
    compute_stats(verify_times, (size_t)sample_idx, &result->verify);
    rc = PQ_SUCCESS;

done:
    free(pk); secure_free(sk, m->sk_size); free(sig);
    free(keygen_times); free(sign_times); free(verify_times);
    return rc;
}

/* ========================================================================
 * Hybrid Benchmark
 * ======================================================================== */

#define HYBRID_SS_MAX 64

/* transcript hash (binds ciphertexts + public keys) followed by combine() */
static int hybrid_combine(const pq_hybrid_kem_t *hybrid,
                          const pq_algorithm_metadata_t *cm,
                          const pq_algorithm_metadata_t *pm,
                          const uint8_t *c_pk, const uint8_t *c_ct, const uint8_t *c_ss,
                          const uint8_t *p_pk, const uint8_t *p_ct, const uint8_t *p_ss,
                          uint8_t out[HYBRID_SS_MAX], size_t *out_len)
{
    uint8_t binding[PQ_COMBINER_TRANSCRIPT_HASH_BYTES];
    int rc = pq_combiner_transcript_hash(c_ct, cm->ct_size, p_ct, pm->ct_size,
                                         c_pk, cm->pk_size, p_pk, pm->pk_size,
                                         binding);
    if (rc != PQ_SUCCESS) return rc;

    *out_len = HYBRID_SS_MAX;
    return hybrid->combiner->combine(c_ss, cm->ss_size, p_ss, pm->ss_size,
                                     out, out_len, binding, sizeof(binding));
}

int pq_bench_hybrid(const pq_hybrid_kem_t *hybrid,
                     const pq_bench_config_t *cfg,
                     pq_hybrid_bench_result_t *result)
{
    if (!hybrid || !cfg || !result) return PQ_ERR_INVALID_PARAMETER;
    if (!bench_cfg_valid(cfg)) return PQ_ERR_INVALID_PARAMETER;
    if (!hybrid->classical || !hybrid->classical->is_available())
        return PQ_ERR_ALGORITHM_NOT_AVAILABLE;
    if (hybrid->pq && !hybrid->pq->is_available())
        return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    const pq_algorithm_metadata_t *cm = hybrid->classical->metadata();
    const pq_algorithm_metadata_t *pm = hybrid->pq ? hybrid->pq->metadata() : NULL;
    if (!cm || !cm->pk_size || !cm->sk_size || !cm->ct_size || !cm->ss_size)
        return PQ_ERR_INVALID_PARAMETER;
    if (hybrid->pq && (!pm || !pm->pk_size || !pm->sk_size || !pm->ct_size || !pm->ss_size))
        return PQ_ERR_INVALID_PARAMETER;
    const bool combining = hybrid->pq && hybrid->combiner;

    memset(result, 0, sizeof(*result));
    result->label = hybrid->label;
    result->nist_level = hybrid->nist_level;
    result->total_pk_bytes = cm->pk_size + (pm ? pm->pk_size : 0);
    result->total_ct_bytes = cm->ct_size + (pm ? pm->ct_size : 0);
    result->total_handshake_bytes = result->total_pk_bytes + result->total_ct_bytes;

    pin_cpu(cfg->cpu_pin);

    int total = cfg->warmup_iterations + cfg->iterations;
    int rc = PQ_ERR_MEMORY_ALLOCATION;
    const char *label = hybrid->label ? hybrid->label : "hybrid";
    double *kg_times  = malloc(sizeof(double) * (size_t)cfg->iterations);
    double *enc_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    double *dec_times = malloc(sizeof(double) * (size_t)cfg->iterations);
    double *comb_times = malloc(sizeof(double) * (size_t)cfg->iterations);

    /* Separate encaps-side and decaps-side secrets so they can be compared */
    uint8_t *c_pk = malloc(cm->pk_size), *c_sk = malloc(cm->sk_size);
    uint8_t *c_ct = malloc(cm->ct_size);
    uint8_t *c_ss_e = malloc(cm->ss_size), *c_ss_d = malloc(cm->ss_size);
    uint8_t *p_pk = NULL, *p_sk = NULL, *p_ct = NULL, *p_ss_e = NULL, *p_ss_d = NULL;
    uint8_t enc_ss[HYBRID_SS_MAX], dec_ss[HYBRID_SS_MAX];
    size_t enc_ss_len = 0, dec_ss_len = 0;

    if (!kg_times || !enc_times || !dec_times || !comb_times ||
        !c_pk || !c_sk || !c_ct || !c_ss_e || !c_ss_d)
        goto done;
    if (pm) {
        p_pk = malloc(pm->pk_size); p_sk = malloc(pm->sk_size);
        p_ct = malloc(pm->ct_size);
        p_ss_e = malloc(pm->ss_size); p_ss_d = malloc(pm->ss_size);
        if (!p_pk || !p_sk || !p_ct || !p_ss_e || !p_ss_d) goto done;
    }

    int sample_idx = 0;
    for (int i = 0; i < total; i++) {
        bool warmup = (i < cfg->warmup_iterations);

        /* Combined keygen */
        uint64_t t0 = clock_ns();
        rc = hybrid->classical->keygen(c_pk, c_sk);
        if (rc == PQ_SUCCESS && pm)
            rc = hybrid->pq->keygen(p_pk, p_sk);
        uint64_t t1 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("keygen", label, i, rc); goto done; }

        /* Combined encapsulate */
        uint64_t t2 = clock_ns();
        rc = hybrid->classical->encapsulate(c_pk, c_ct, c_ss_e);
        if (rc == PQ_SUCCESS && pm)
            rc = hybrid->pq->encapsulate(p_pk, p_ct, p_ss_e);
        uint64_t t3 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("encapsulate", label, i, rc); goto done; }

        /* Combiner (sender side) */
        uint64_t t4 = clock_ns();
        if (combining)
            rc = hybrid_combine(hybrid, cm, pm, c_pk, c_ct, c_ss_e, p_pk, p_ct, p_ss_e,
                                enc_ss, &enc_ss_len);
        uint64_t t5 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("combine", label, i, rc); goto done; }

        /* Combined decapsulate (including the receiver-side combiner) */
        uint64_t t6 = clock_ns();
        rc = hybrid->classical->decapsulate(c_sk, c_ct, c_ss_d);
        if (rc == PQ_SUCCESS && pm)
            rc = hybrid->pq->decapsulate(p_sk, p_ct, p_ss_d);
        if (rc == PQ_SUCCESS && combining)
            rc = hybrid_combine(hybrid, cm, pm, c_pk, c_ct, c_ss_d, p_pk, p_ct, p_ss_d,
                                dec_ss, &dec_ss_len);
        uint64_t t7 = clock_ns();
        if (rc != PQ_SUCCESS) { bench_fail("decapsulate", label, i, rc); goto done; }

        /* Correctness: both sides must derive the same secret(s) */
        bool match;
        if (combining) {
            match = enc_ss_len == dec_ss_len && enc_ss_len > 0 &&
                    CRYPTO_memcmp(enc_ss, dec_ss, enc_ss_len) == 0;
        } else {
            match = CRYPTO_memcmp(c_ss_e, c_ss_d, cm->ss_size) == 0 &&
                    (!pm || CRYPTO_memcmp(p_ss_e, p_ss_d, pm->ss_size) == 0);
        }
        if (!match) {
            rc = bench_fail("shared-secret check", label, i, PQ_ERR_CRYPTO_FAILED);
            goto done;
        }

        if (!warmup && sample_idx < cfg->iterations) {
            kg_times[sample_idx]   = (double)(t1 - t0) / 1000.0;
            enc_times[sample_idx]  = (double)(t3 - t2) / 1000.0;
            comb_times[sample_idx] = (double)(t5 - t4) / 1000.0;
            dec_times[sample_idx]  = (double)(t7 - t6) / 1000.0;
            sample_idx++;
        }
    }

    compute_stats(kg_times, (size_t)sample_idx, &result->hybrid_keygen);
    compute_stats(enc_times, (size_t)sample_idx, &result->hybrid_encapsulate);
    compute_stats(dec_times, (size_t)sample_idx, &result->hybrid_decapsulate);
    compute_stats(comb_times, (size_t)sample_idx, &result->combine);
    rc = PQ_SUCCESS;

done:
    OPENSSL_cleanse(enc_ss, sizeof(enc_ss));
    OPENSSL_cleanse(dec_ss, sizeof(dec_ss));
    free(c_pk); secure_free(c_sk, cm->sk_size); free(c_ct);
    secure_free(c_ss_e, cm->ss_size); secure_free(c_ss_d, cm->ss_size);
    if (pm) {
        free(p_pk); secure_free(p_sk, pm->sk_size); free(p_ct);
        secure_free(p_ss_e, pm->ss_size); secure_free(p_ss_d, pm->ss_size);
    }
    free(kg_times); free(enc_times); free(dec_times); free(comb_times);
    return rc;
}

/* ========================================================================
 * Batch Benchmarks
 * ======================================================================== */

size_t pq_bench_all_kems(const pq_registry_t *reg,
                          const pq_bench_config_t *cfg,
                          pq_kem_bench_result_t *results, size_t max)
{
    const pq_kem_provider_t *providers[PQ_REGISTRY_MAX_KEM_PROVIDERS];
    size_t count = pq_registry_list_kems(reg, providers, PQ_REGISTRY_MAX_KEM_PROVIDERS);

    size_t n = 0;
    for (size_t i = 0; i < count && n < max; i++) {
        if (cfg->verbose)
            fprintf(stderr, "[bench] KEM: %s...\n", providers[i]->name());
        int rc = pq_bench_kem(providers[i], cfg, &results[n]);
        if (rc == PQ_SUCCESS)
            n++;
        else if (rc == PQ_ERR_ALGORITHM_NOT_AVAILABLE && cfg->verbose)
            fprintf(stderr, "[bench] KEM %s: not available, skipped\n", providers[i]->name());
        else if (rc != PQ_ERR_ALGORITHM_NOT_AVAILABLE)
            fprintf(stderr, "[bench] KEM %s: benchmark aborted (%s)\n",
                    providers[i]->name(), pq_error_string(rc));
    }
    return n;
}

size_t pq_bench_all_hybrids(const pq_registry_t *reg,
                             const pq_bench_config_t *cfg,
                             pq_hybrid_bench_result_t *results, size_t max)
{
    const pq_hybrid_kem_t *hybrids[PQ_REGISTRY_MAX_HYBRID_KEMS];
    size_t count = pq_registry_list_hybrids(reg, hybrids, PQ_REGISTRY_MAX_HYBRID_KEMS);

    size_t n = 0;
    for (size_t i = 0; i < count && n < max; i++) {
        if (!hybrids[i]->pq) continue; /* skip classical-only for hybrid bench */
        if (cfg->verbose)
            fprintf(stderr, "[bench] Hybrid: %s...\n", hybrids[i]->label);
        int rc = pq_bench_hybrid(hybrids[i], cfg, &results[n]);
        if (rc == PQ_SUCCESS)
            n++;
        else if (rc == PQ_ERR_ALGORITHM_NOT_AVAILABLE && cfg->verbose)
            fprintf(stderr, "[bench] Hybrid %s: not available, skipped\n", hybrids[i]->label);
        else if (rc != PQ_ERR_ALGORITHM_NOT_AVAILABLE)
            fprintf(stderr, "[bench] Hybrid %s: benchmark aborted (%s)\n",
                    hybrids[i]->label, pq_error_string(rc));
    }
    return n;
}

/* ========================================================================
 * Output: Formatted Table
 * ======================================================================== */

void pq_bench_print_kem_results(const pq_kem_bench_result_t *results, size_t count)
{
    printf("\n%-16s %5s  %10s %10s %10s  %10s %10s %10s  %6s\n",
           "Algorithm", "NIST", "kg(us)", "enc(us)", "dec(us)",
           "kg_p95", "enc_p95", "dec_p95", "wire(B)");
    printf("%-16s %5s  %10s %10s %10s  %10s %10s %10s  %6s\n",
           "----------------", "-----",
           "----------", "----------", "----------",
           "----------", "----------", "----------", "------");

    for (size_t i = 0; i < count; i++) {
        const pq_kem_bench_result_t *r = &results[i];
        printf("%-16s %5d  %10.2f %10.2f %10.2f  %10.2f %10.2f %10.2f  %6zu\n",
               r->algorithm_name, r->nist_level,
               r->keygen.mean_us, r->encapsulate.mean_us, r->decapsulate.mean_us,
               r->keygen.p95_us, r->encapsulate.p95_us, r->decapsulate.p95_us,
               r->total_handshake_bytes);
    }
    printf("\n");
}

void pq_bench_print_hybrid_results(const pq_hybrid_bench_result_t *results, size_t count)
{
    printf("\n%-24s %5s  %10s %10s %10s %10s  %6s\n",
           "Hybrid", "NIST", "kg(us)", "enc(us)", "dec(us)", "comb(us)", "wire(B)");
    printf("%-24s %5s  %10s %10s %10s %10s  %6s\n",
           "------------------------", "-----",
           "----------", "----------", "----------", "----------", "------");

    for (size_t i = 0; i < count; i++) {
        const pq_hybrid_bench_result_t *r = &results[i];
        printf("%-24s %5d  %10.2f %10.2f %10.2f %10.2f  %6zu\n",
               r->label, r->nist_level,
               r->hybrid_keygen.mean_us, r->hybrid_encapsulate.mean_us,
               r->hybrid_decapsulate.mean_us, r->combine.mean_us,
               r->total_handshake_bytes);
    }
    printf("\n");
}

/* ========================================================================
 * Export: CSV
 * ======================================================================== */

int pq_bench_export_csv(const char *filename,
                         const pq_kem_bench_result_t *kem_results, size_t kem_count,
                         const pq_hybrid_bench_result_t *hybrid_results, size_t hybrid_count)
{
    FILE *f = fopen(filename, "w");
    if (!f) return PQ_ERR_CONFIG_SAVE_FAILED;

    /* KEM results */
    fprintf(f, "type,algorithm,nist_level,family,"
               "keygen_mean_us,keygen_p95_us,keygen_ci95_low,keygen_ci95_high,"
               "encaps_mean_us,encaps_p95_us,encaps_ci95_low,encaps_ci95_high,"
               "decaps_mean_us,decaps_p95_us,decaps_ci95_low,decaps_ci95_high,"
               "pk_bytes,ct_bytes,wire_bytes,samples\n");

    for (size_t i = 0; i < kem_count; i++) {
        const pq_kem_bench_result_t *r = &kem_results[i];
        fprintf(f, "kem,%s,%d,%d,"
                   "%.3f,%.3f,%.3f,%.3f,"
                   "%.3f,%.3f,%.3f,%.3f,"
                   "%.3f,%.3f,%.3f,%.3f,"
                   "%zu,%zu,%zu,%zu\n",
                r->algorithm_name, r->nist_level, r->family,
                r->keygen.mean_us, r->keygen.p95_us,
                r->keygen.ci95_low, r->keygen.ci95_high,
                r->encapsulate.mean_us, r->encapsulate.p95_us,
                r->encapsulate.ci95_low, r->encapsulate.ci95_high,
                r->decapsulate.mean_us, r->decapsulate.p95_us,
                r->decapsulate.ci95_low, r->decapsulate.ci95_high,
                r->pk_bytes, r->ct_bytes, r->total_handshake_bytes,
                r->keygen.samples);
    }

    /* Hybrid results */
    for (size_t i = 0; i < hybrid_count; i++) {
        const pq_hybrid_bench_result_t *r = &hybrid_results[i];
        fprintf(f, "hybrid,%s,%d,5,"
                   "%.3f,%.3f,%.3f,%.3f,"
                   "%.3f,%.3f,%.3f,%.3f,"
                   "%.3f,%.3f,%.3f,%.3f,"
                   "%zu,%zu,%zu,%zu\n",
                r->label, r->nist_level,
                r->hybrid_keygen.mean_us, r->hybrid_keygen.p95_us,
                r->hybrid_keygen.ci95_low, r->hybrid_keygen.ci95_high,
                r->hybrid_encapsulate.mean_us, r->hybrid_encapsulate.p95_us,
                r->hybrid_encapsulate.ci95_low, r->hybrid_encapsulate.ci95_high,
                r->hybrid_decapsulate.mean_us, r->hybrid_decapsulate.p95_us,
                r->hybrid_decapsulate.ci95_low, r->hybrid_decapsulate.ci95_high,
                r->total_pk_bytes, r->total_ct_bytes, r->total_handshake_bytes,
                r->hybrid_keygen.samples);
    }

    fclose(f);
    return PQ_SUCCESS;
}

/* ========================================================================
 * Export: JSON
 * ======================================================================== */

int pq_bench_export_json(const char *filename,
                          const pq_kem_bench_result_t *kem_results, size_t kem_count,
                          const pq_hybrid_bench_result_t *hybrid_results, size_t hybrid_count)
{
    FILE *f = fopen(filename, "w");
    if (!f) return PQ_ERR_CONFIG_SAVE_FAILED;

    fprintf(f, "{\n  \"kem_benchmarks\": [\n");
    for (size_t i = 0; i < kem_count; i++) {
        const pq_kem_bench_result_t *r = &kem_results[i];
        fprintf(f, "    {\"algorithm\":\"%s\",\"nist_level\":%d,"
                   "\"keygen\":{\"mean_us\":%.3f,\"p95_us\":%.3f,\"ci95\":[%.3f,%.3f]},"
                   "\"encapsulate\":{\"mean_us\":%.3f,\"p95_us\":%.3f,\"ci95\":[%.3f,%.3f]},"
                   "\"decapsulate\":{\"mean_us\":%.3f,\"p95_us\":%.3f,\"ci95\":[%.3f,%.3f]},"
                   "\"wire_bytes\":%zu,\"samples\":%zu}%s\n",
                r->algorithm_name, r->nist_level,
                r->keygen.mean_us, r->keygen.p95_us,
                r->keygen.ci95_low, r->keygen.ci95_high,
                r->encapsulate.mean_us, r->encapsulate.p95_us,
                r->encapsulate.ci95_low, r->encapsulate.ci95_high,
                r->decapsulate.mean_us, r->decapsulate.p95_us,
                r->decapsulate.ci95_low, r->decapsulate.ci95_high,
                r->total_handshake_bytes, r->keygen.samples,
                i < kem_count - 1 ? "," : "");
    }

    fprintf(f, "  ],\n  \"hybrid_benchmarks\": [\n");
    for (size_t i = 0; i < hybrid_count; i++) {
        const pq_hybrid_bench_result_t *r = &hybrid_results[i];
        fprintf(f, "    {\"label\":\"%s\",\"nist_level\":%d,"
                   "\"keygen\":{\"mean_us\":%.3f,\"p95_us\":%.3f},"
                   "\"encapsulate\":{\"mean_us\":%.3f,\"p95_us\":%.3f},"
                   "\"decapsulate\":{\"mean_us\":%.3f,\"p95_us\":%.3f},"
                   "\"combine\":{\"mean_us\":%.3f,\"p95_us\":%.3f},"
                   "\"wire_bytes\":%zu}%s\n",
                r->label, r->nist_level,
                r->hybrid_keygen.mean_us, r->hybrid_keygen.p95_us,
                r->hybrid_encapsulate.mean_us, r->hybrid_encapsulate.p95_us,
                r->hybrid_decapsulate.mean_us, r->hybrid_decapsulate.p95_us,
                r->combine.mean_us, r->combine.p95_us,
                r->total_handshake_bytes,
                i < hybrid_count - 1 ? "," : "");
    }
    fprintf(f, "  ]\n}\n");

    fclose(f);
    return PQ_SUCCESS;
}
