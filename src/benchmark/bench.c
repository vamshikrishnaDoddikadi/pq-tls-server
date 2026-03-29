/**
 * @file bench.c
 * @brief PQ algorithm benchmarking implementation
 * @author Vamshi Krishna Doddikadi
 */

#include "bench.h"
#include "../common/pq_kem.h"
#include "../common/pq_sig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* ======================================================================== */
/* Timing helpers                                                           */
/* ======================================================================== */

typedef struct {
    const char *name;
    double      mean_us;    /* microseconds */
    double      stddev_us;
    double      min_us;
    double      max_us;
    int         iterations;
} bench_result_t;

static double timespec_diff_us(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1e6 +
           (end->tv_nsec - start->tv_nsec) / 1e3;
}

static void compute_stats(double *samples, int n, bench_result_t *r) {
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

/* ======================================================================== */
/* Individual benchmarks                                                    */
/* ======================================================================== */

static void bench_kem(int alg, const char *name, int iters, bench_result_t *keygen_r,
                      bench_result_t *encaps_r, bench_result_t *decaps_r) {
    double *kg_times = malloc(sizeof(double) * (size_t)iters);
    double *enc_times = malloc(sizeof(double) * (size_t)iters);
    double *dec_times = malloc(sizeof(double) * (size_t)iters);

    /* Use size query functions to allocate properly */
    size_t pk_size = pq_kem_publickey_bytes(alg);
    size_t sk_size = pq_kem_secretkey_bytes(alg);
    size_t ct_size = pq_kem_ciphertext_bytes(alg);
    size_t ss_size = pq_kem_sharedsecret_bytes(alg);

    if (pk_size == 0 || sk_size == 0 || ct_size == 0 || ss_size == 0) {
        fprintf(stderr, "Unknown KEM algorithm: %d\n", alg);
        free(kg_times); free(enc_times); free(dec_times);
        keygen_r->name = name; keygen_r->mean_us = 0;
        encaps_r->name = name; encaps_r->mean_us = 0;
        decaps_r->name = name; decaps_r->mean_us = 0;
        return;
    }

    uint8_t *pk = malloc(pk_size);
    uint8_t *sk = malloc(sk_size);
    uint8_t *ct = malloc(ct_size);
    uint8_t *ss_enc = malloc(ss_size);
    uint8_t *ss_dec = malloc(ss_size);

    struct timespec t1, t2;

    for (int i = 0; i < iters; i++) {
        /* Keygen */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pq_kem_keypair(alg, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        kg_times[i] = timespec_diff_us(&t1, &t2);

        /* Encapsulate */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pq_kem_encapsulate(alg, ct, ss_enc, pk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        enc_times[i] = timespec_diff_us(&t1, &t2);

        /* Decapsulate */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pq_kem_decapsulate(alg, ss_dec, ct, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        dec_times[i] = timespec_diff_us(&t1, &t2);

        /* Clean sensitive data */
        memset(sk, 0, sk_size);
        memset(ss_enc, 0, ss_size);
        memset(ss_dec, 0, ss_size);
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "%s keygen", name);
    keygen_r->name = strdup(buf);
    compute_stats(kg_times, iters, keygen_r);

    snprintf(buf, sizeof(buf), "%s encaps", name);
    encaps_r->name = strdup(buf);
    compute_stats(enc_times, iters, encaps_r);

    snprintf(buf, sizeof(buf), "%s decaps", name);
    decaps_r->name = strdup(buf);
    compute_stats(dec_times, iters, decaps_r);

    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    free(kg_times); free(enc_times); free(dec_times);
}

static void bench_sig(int alg, const char *name, int iters, bench_result_t *keygen_r,
                      bench_result_t *sign_r, bench_result_t *verify_r) {
    double *kg_times = malloc(sizeof(double) * (size_t)iters);
    double *sig_times = malloc(sizeof(double) * (size_t)iters);
    double *ver_times = malloc(sizeof(double) * (size_t)iters);

    /* Use max sizes from the sig header for stack allocation */
    uint8_t pk[PQ_SIG_MLDSA87_PUBLICKEY_BYTES];
    uint8_t sk[PQ_SIG_MLDSA87_SECRETKEY_BYTES];
    uint8_t sig[PQ_SIG_MLDSA87_SIGNATURE_BYTES];
    size_t sig_len = 0;
    const uint8_t msg[] = "Benchmark test message for PQ-TLS Server";
    struct timespec t1, t2;

    for (int i = 0; i < iters; i++) {
        /* Keygen */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pq_sig_keypair(alg, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        kg_times[i] = timespec_diff_us(&t1, &t2);

        /* Sign */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pq_sig_sign(alg, sig, &sig_len, msg, sizeof(msg), sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        sig_times[i] = timespec_diff_us(&t1, &t2);

        /* Verify */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pq_sig_verify(alg, msg, sizeof(msg), sig, sig_len, pk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        ver_times[i] = timespec_diff_us(&t1, &t2);

        memset(sk, 0, sizeof(sk));
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "%s keygen", name);
    keygen_r->name = strdup(buf);
    compute_stats(kg_times, iters, keygen_r);

    snprintf(buf, sizeof(buf), "%s sign", name);
    sign_r->name = strdup(buf);
    compute_stats(sig_times, iters, sign_r);

    snprintf(buf, sizeof(buf), "%s verify", name);
    verify_r->name = strdup(buf);
    compute_stats(ver_times, iters, verify_r);

    free(kg_times);
    free(sig_times);
    free(ver_times);
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

    /* Up to 18 results: 3 KEM algos * 3 ops + 3 SIG algos * 3 ops */
    bench_result_t results[24];
    int count = 0;

    /* --- KEM benchmarks --- */
    printf("\nRunning ML-KEM-512...\n");
    bench_kem(PQ_KEM_MLKEM512, "ML-KEM-512", iterations,
              &results[count], &results[count+1], &results[count+2]);
    count += 3;

    printf("Running ML-KEM-768...\n");
    bench_kem(PQ_KEM_MLKEM768, "ML-KEM-768", iterations,
              &results[count], &results[count+1], &results[count+2]);
    count += 3;

    printf("Running ML-KEM-1024...\n");
    bench_kem(PQ_KEM_MLKEM1024, "ML-KEM-1024", iterations,
              &results[count], &results[count+1], &results[count+2]);
    count += 3;

    /* --- Signature benchmarks --- */
    printf("Running ML-DSA-44...\n");
    bench_sig(PQ_SIG_MLDSA44, "ML-DSA-44", iterations,
              &results[count], &results[count+1], &results[count+2]);
    count += 3;

    printf("Running ML-DSA-65...\n");
    bench_sig(PQ_SIG_MLDSA65, "ML-DSA-65", iterations,
              &results[count], &results[count+1], &results[count+2]);
    count += 3;

    printf("Running Ed25519...\n");
    bench_sig(PQ_SIG_ED25519, "Ed25519", iterations,
              &results[count], &results[count+1], &results[count+2]);
    count += 3;

    /* --- Output --- */
    switch (format) {
    case PQ_BENCH_FORMAT_TABLE: print_table(results, count); break;
    case PQ_BENCH_FORMAT_JSON:  print_json(results, count);  break;
    case PQ_BENCH_FORMAT_CSV:   print_csv(results, count);   break;
    }

    /* Free strdup'd names */
    for (int i = 0; i < count; i++) {
        free((void*)results[i].name);
    }

    return 0;
}
