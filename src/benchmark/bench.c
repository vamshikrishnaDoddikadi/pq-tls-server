/**
 * @file bench.c
 * @brief PQ algorithm benchmarking implementation
 * @author Vamshi Krishna Doddikadi
 */

#include "bench.h"
#include "../common/pq_kem.h"
#include "../common/pq_sig.h"
#include "../common/pq_errors.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* ======================================================================== */
/* Timing helpers                                                           */
/* ======================================================================== */

typedef struct {
    char       *name;       /* heap-allocated, freed by pq_bench_run() */
    double      mean_us;    /* microseconds */
    double      stddev_us;
    double      min_us;
    double      max_us;
    int         iterations;
} bench_result_t;

static double timespec_diff_us(struct timespec *start, struct timespec *end) {
    return (double)(end->tv_sec - start->tv_sec) * 1e6 +
           (double)(end->tv_nsec - start->tv_nsec) / 1e3;
}

static void compute_stats(const double *samples, int n, bench_result_t *r) {
    if (!samples || n <= 0) {
        r->mean_us = r->stddev_us = r->min_us = r->max_us = 0.0;
        r->iterations = 0;
        return;
    }

    double sum = 0, min = samples[0], max = samples[0];
    for (int i = 0; i < n; i++) {
        sum += samples[i];
        if (samples[i] < min) min = samples[i];
        if (samples[i] > max) max = samples[i];
    }
    r->mean_us = sum / n;
    r->min_us = min;
    r->max_us = max;
    r->iterations = n;

    double var = 0;
    for (int i = 0; i < n; i++) {
        double d = samples[i] - r->mean_us;
        var += d * d;
    }
    r->stddev_us = sqrt(var / n);
}

/* Name + stats; returns PQ_ERR_MEMORY_ALLOCATION if the name cannot be stored */
static int finish_result(bench_result_t *r, const char *alg, const char *op,
                         const double *samples, int n) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s %s", alg, op);
    r->name = strdup(buf);
    compute_stats(samples, n, r);
    return r->name ? PQ_SUCCESS : PQ_ERR_MEMORY_ALLOCATION;
}

/* ======================================================================== */
/* Individual benchmarks                                                    */
/*                                                                          */
/* Every operation's return value is checked and the benchmark aborts on    */
/* the first failure (never time an error path).  KEM runs also check that  */
/* both sides derived the same shared secret; signature runs check that the */
/* signature verifies.                                                      */
/* ======================================================================== */

static int bench_kem(int alg, const char *name, int iters, bench_result_t *keygen_r,
                     bench_result_t *encaps_r, bench_result_t *decaps_r) {
    int rc = PQ_ERR_MEMORY_ALLOCATION;
    uint8_t *pk = NULL, *sk = NULL, *ct = NULL, *ss_enc = NULL, *ss_dec = NULL;
    double *kg_times = NULL, *enc_times = NULL, *dec_times = NULL;

    /* Use size query functions to allocate properly */
    size_t pk_size = pq_kem_publickey_bytes(alg);
    size_t sk_size = pq_kem_secretkey_bytes(alg);
    size_t ct_size = pq_kem_ciphertext_bytes(alg);
    size_t ss_size = pq_kem_sharedsecret_bytes(alg);

    if (iters <= 0 || pk_size == 0 || sk_size == 0 || ct_size == 0 || ss_size == 0) {
        fprintf(stderr, "Unknown KEM algorithm: %d\n", alg);
        return PQ_ERR_INVALID_ALGORITHM;
    }

    kg_times = malloc(sizeof(double) * (size_t)iters);
    enc_times = malloc(sizeof(double) * (size_t)iters);
    dec_times = malloc(sizeof(double) * (size_t)iters);
    pk = malloc(pk_size);
    sk = malloc(sk_size);
    ct = malloc(ct_size);
    ss_enc = malloc(ss_size);
    ss_dec = malloc(ss_size);
    if (!kg_times || !enc_times || !dec_times || !pk || !sk || !ct || !ss_enc || !ss_dec) {
        fprintf(stderr, "%s: out of memory\n", name);
        goto done;
    }

    struct timespec t1, t2;

    for (int i = 0; i < iters; i++) {
        /* Keygen */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        rc = pq_kem_keypair(alg, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (rc != PQ_SUCCESS) {
            fprintf(stderr, "%s keygen failed: %s\n", name, pq_error_string(rc));
            goto done;
        }
        kg_times[i] = timespec_diff_us(&t1, &t2);

        /* Encapsulate */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        rc = pq_kem_encapsulate(alg, ct, ss_enc, pk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (rc != PQ_SUCCESS) {
            fprintf(stderr, "%s encaps failed: %s\n", name, pq_error_string(rc));
            goto done;
        }
        enc_times[i] = timespec_diff_us(&t1, &t2);

        /* Decapsulate */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        rc = pq_kem_decapsulate(alg, ss_dec, ct, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (rc != PQ_SUCCESS) {
            fprintf(stderr, "%s decaps failed: %s\n", name, pq_error_string(rc));
            goto done;
        }
        dec_times[i] = timespec_diff_us(&t1, &t2);

        /* Correctness: both sides must agree */
        if (CRYPTO_memcmp(ss_enc, ss_dec, ss_size) != 0) {
            fprintf(stderr, "%s: shared secret mismatch (iteration %d)\n", name, i);
            rc = PQ_ERR_CRYPTO_FAILED;
            goto done;
        }

        /* Clean sensitive data */
        OPENSSL_cleanse(sk, sk_size);
        OPENSSL_cleanse(ss_enc, ss_size);
        OPENSSL_cleanse(ss_dec, ss_size);
    }

    rc = finish_result(keygen_r, name, "keygen", kg_times, iters);
    if (rc == PQ_SUCCESS) rc = finish_result(encaps_r, name, "encaps", enc_times, iters);
    if (rc == PQ_SUCCESS) rc = finish_result(decaps_r, name, "decaps", dec_times, iters);

done:
    if (sk) OPENSSL_cleanse(sk, sk_size);
    if (ss_enc) OPENSSL_cleanse(ss_enc, ss_size);
    if (ss_dec) OPENSSL_cleanse(ss_dec, ss_size);
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    free(kg_times); free(enc_times); free(dec_times);
    return rc;
}

static int bench_sig(int alg, const char *name, int iters, bench_result_t *keygen_r,
                     bench_result_t *sign_r, bench_result_t *verify_r) {
    int rc = PQ_ERR_MEMORY_ALLOCATION;
    uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    double *kg_times = NULL, *sig_times = NULL, *ver_times = NULL;

    size_t pk_size = pq_sig_publickey_bytes(alg);
    size_t sk_size = pq_sig_secretkey_bytes(alg);
    size_t sig_cap = pq_sig_signature_bytes(alg);
    if (iters <= 0 || pk_size == 0 || sk_size == 0 || sig_cap == 0) {
        fprintf(stderr, "Unknown signature algorithm: %d\n", alg);
        return PQ_ERR_INVALID_ALGORITHM;
    }

    kg_times = malloc(sizeof(double) * (size_t)iters);
    sig_times = malloc(sizeof(double) * (size_t)iters);
    ver_times = malloc(sizeof(double) * (size_t)iters);
    pk = malloc(pk_size);
    sk = malloc(sk_size);
    sig = malloc(sig_cap);
    if (!kg_times || !sig_times || !ver_times || !pk || !sk || !sig) {
        fprintf(stderr, "%s: out of memory\n", name);
        goto done;
    }

    const uint8_t msg[] = "Benchmark test message for PQ-TLS Server";
    struct timespec t1, t2;

    for (int i = 0; i < iters; i++) {
        /* Keygen */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        rc = pq_sig_keypair(alg, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (rc != PQ_SUCCESS) {
            fprintf(stderr, "%s keygen failed: %s\n", name, pq_error_string(rc));
            goto done;
        }
        kg_times[i] = timespec_diff_us(&t1, &t2);

        /* Sign: *sig_len is the buffer capacity on input and must be reset
         * before every call (it is overwritten with the signature length). */
        size_t sig_len = sig_cap;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        rc = pq_sig_sign(alg, sig, &sig_len, msg, sizeof(msg), sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (rc != PQ_SUCCESS || sig_len == 0 || sig_len > sig_cap) {
            fprintf(stderr, "%s sign failed: %s\n", name, pq_error_string(rc));
            if (rc == PQ_SUCCESS) rc = PQ_ERR_SIGNATURE_FAILED;
            goto done;
        }
        sig_times[i] = timespec_diff_us(&t1, &t2);

        /* Verify (must succeed) */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        rc = pq_sig_verify(alg, msg, sizeof(msg), sig, sig_len, pk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (rc != PQ_SUCCESS) {
            fprintf(stderr, "%s verify failed: %s\n", name, pq_error_string(rc));
            goto done;
        }
        ver_times[i] = timespec_diff_us(&t1, &t2);

        OPENSSL_cleanse(sk, sk_size);
    }

    rc = finish_result(keygen_r, name, "keygen", kg_times, iters);
    if (rc == PQ_SUCCESS) rc = finish_result(sign_r, name, "sign", sig_times, iters);
    if (rc == PQ_SUCCESS) rc = finish_result(verify_r, name, "verify", ver_times, iters);

done:
    if (sk) OPENSSL_cleanse(sk, sk_size);
    free(pk); free(sk); free(sig);
    free(kg_times); free(sig_times); free(ver_times);
    return rc;
}

/* ======================================================================== */
/* Output formatters                                                        */
/* ======================================================================== */

static void print_table(bench_result_t *results, int count) {
    printf("\n%-28s %12s %12s %12s %12s %8s\n",
           "Operation", "Mean (us)", "StdDev", "Min (us)", "Max (us)", "Iters");
    printf("%-28s %12s %12s %12s %12s %8s\n",
           "----------------------------", "------------", "------------",
           "------------", "------------", "--------");

    for (int i = 0; i < count; i++) {
        bench_result_t *r = &results[i];
        printf("%-28s %12.1f %12.1f %12.1f %12.1f %8d\n",
               r->name, r->mean_us, r->stddev_us, r->min_us, r->max_us,
               r->iterations);
    }
    printf("\n");
}

static void print_json(bench_result_t *results, int count) {
    printf("[\n");
    for (int i = 0; i < count; i++) {
        bench_result_t *r = &results[i];
        printf("  {\"operation\":\"%s\",\"mean_us\":%.1f,\"stddev_us\":%.1f,"
               "\"min_us\":%.1f,\"max_us\":%.1f,\"iterations\":%d}%s\n",
               r->name, r->mean_us, r->stddev_us, r->min_us, r->max_us,
               r->iterations, (i < count - 1) ? "," : "");
    }
    printf("]\n");
}

static void print_csv(bench_result_t *results, int count) {
    printf("operation,mean_us,stddev_us,min_us,max_us,iterations\n");
    for (int i = 0; i < count; i++) {
        bench_result_t *r = &results[i];
        printf("%s,%.1f,%.1f,%.1f,%.1f,%d\n",
               r->name, r->mean_us, r->stddev_us, r->min_us, r->max_us,
               r->iterations);
    }
}

/* ======================================================================== */
/* Public API                                                               */
/* ======================================================================== */

int pq_bench_run(int iterations, pq_bench_format_t format) {
    if (iterations <= 0) iterations = 1000;

    printf("PQ-TLS Server Benchmark Suite\n");
    printf("Iterations: %d\n", iterations);

    static const struct {
        int is_sig;
        int alg;
        const char *name;
    } suite[] = {
        { 0, PQ_KEM_MLKEM512,  "ML-KEM-512"  },
        { 0, PQ_KEM_MLKEM768,  "ML-KEM-768"  },
        { 0, PQ_KEM_MLKEM1024, "ML-KEM-1024" },
        { 1, PQ_SIG_MLDSA44,   "ML-DSA-44"   },
        { 1, PQ_SIG_MLDSA65,   "ML-DSA-65"   },
        { 1, PQ_SIG_ED25519,   "Ed25519"     },
    };
    enum { N_SUITE = sizeof(suite) / sizeof(suite[0]) };

    /* 3 results (keygen + 2 ops) per algorithm */
    bench_result_t results[N_SUITE * 3];
    memset(results, 0, sizeof(results));
    int count = 0;
    int rc = PQ_SUCCESS;

    for (size_t i = 0; i < N_SUITE; i++) {
        printf("Running %s...\n", suite[i].name);
        if (suite[i].is_sig) {
            rc = bench_sig(suite[i].alg, suite[i].name, iterations,
                           &results[count], &results[count + 1], &results[count + 2]);
        } else {
            rc = bench_kem(suite[i].alg, suite[i].name, iterations,
                           &results[count], &results[count + 1], &results[count + 2]);
        }
        if (rc != PQ_SUCCESS) {
            fprintf(stderr, "Benchmark aborted: %s failed (%s)\n",
                    suite[i].name, pq_error_string(rc));
            break;
        }
        count += 3;
    }

    /* --- Output (only fully successful runs) --- */
    if (rc == PQ_SUCCESS) {
        switch (format) {
        case PQ_BENCH_FORMAT_TABLE: print_table(results, count); break;
        case PQ_BENCH_FORMAT_JSON:  print_json(results, count);  break;
        case PQ_BENCH_FORMAT_CSV:   print_csv(results, count);   break;
        }
    }

    /* Free strdup'd names (including a partially filled failed entry) */
    for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
        free(results[i].name);
    }

    return rc == PQ_SUCCESS ? 0 : 1;
}
