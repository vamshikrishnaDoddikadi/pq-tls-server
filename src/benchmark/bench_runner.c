/**
 * @file bench_runner.c
 * @brief CLI tool for running the ML-KEM Hybrid Benchmark Suite
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Usage:
 *   ./bench_runner [options]
 *
 * Options:
 *   -n <iterations>     Number of iterations (default: 1000)
 *   -w <warmup>         Warmup iterations (default: 100)
 *   -c <cpu>            Pin to CPU core (default: no pinning)
 *   -o <file.csv>       Export CSV results
 *   -j <file.json>      Export JSON results
 *   -p <plugin-dir>     Load algorithm plugins from directory
 *   -a <algorithm>      Benchmark specific algorithm only
 *   -v                  Verbose output
 *   -h                  Show help
 */

#include "bench_agility.h"
#include "../common/crypto_registry.h"
#include "../common/hybrid_combiner.h"
#include "../common/kem_hqc.h"
#include "../common/pq_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "ML-KEM Hybrid Benchmark Suite\n"
        "Usage: %s [options]\n\n"
        "Options:\n"
        "  -n <iterations>   Number of measurement iterations (default: 1000)\n"
        "  -w <warmup>       Warmup iterations to discard (default: 100)\n"
        "  -c <cpu>          Pin to CPU core (default: no pinning)\n"
        "  -o <file.csv>     Export results to CSV\n"
        "  -j <file.json>    Export results to JSON\n"
        "  -p <dir>          Load algorithm plugins from directory\n"
        "  -a <name>         Benchmark specific algorithm only\n"
        "  -v                Verbose output\n"
        "  -h                Show this help\n"
        "\n", prog);
}

int main(int argc, char **argv)
{
    pq_bench_config_t cfg;
    pq_bench_config_default(&cfg);

    const char *csv_file = NULL;
    const char *json_file = NULL;
    const char *plugin_dir = NULL;
    const char *specific_alg = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "n:w:c:o:j:p:a:vh")) != -1) {
        switch (opt) {
            case 'n': cfg.iterations = atoi(optarg); break;
            case 'w': cfg.warmup_iterations = atoi(optarg); break;
            case 'c': cfg.cpu_pin = atoi(optarg); break;
            case 'o': csv_file = optarg; break;
            case 'j': json_file = optarg; break;
            case 'p': plugin_dir = optarg; break;
            case 'a': specific_alg = optarg; break;
            case 'v': cfg.verbose = 1; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    /* Print header */
    time_t now = time(NULL);
    printf("=============================================================\n");
    printf("  ML-KEM Hybrid Benchmark Suite\n");
    printf("  Date: %s", ctime(&now));
    printf("  Iterations: %d (warmup: %d)\n", cfg.iterations, cfg.warmup_iterations);
    if (cfg.cpu_pin >= 0)
        printf("  CPU pin: core %d\n", cfg.cpu_pin);
    printf("=============================================================\n");

    /* Create registry and load providers */
    pq_registry_t *reg = pq_registry_create();
    if (!reg) {
        fprintf(stderr, "Failed to create registry\n");
        return 1;
    }

    int rc = pq_registry_register_builtins(reg);
    if (rc != PQ_SUCCESS) {
        fprintf(stderr, "Failed to register builtins: %s\n", pq_error_string(rc));
        pq_registry_destroy(reg);
        return 1;
    }

    /* Also register HQC as a built-in for benchmarking */
    pq_registry_register_kem(reg, pq_kem_provider_hqc128());
    pq_registry_register_kem(reg, pq_kem_provider_hqc192());
    pq_registry_register_kem(reg, pq_kem_provider_hqc256());

    /* Register HQC hybrids */
    pq_hybrid_kem_t h_x25519_hqc128 = {
        .label = "X25519 + HQC-128", .tls_group = "X25519HQC128",
        .classical = pq_registry_find_kem(reg, "X25519"),
        .pq = pq_registry_find_kem(reg, "HQC-128"),
        .combiner = pq_combiner_kdf_concat(), .nist_level = 1,
    };
    pq_registry_register_hybrid(reg, &h_x25519_hqc128);

    /* Load plugins if specified */
    if (plugin_dir) {
        int loaded = pq_registry_load_plugins(reg, plugin_dir);
        printf("Loaded %d plugins from %s\n", loaded, plugin_dir);
    }

    printf("\nRegistered: %zu KEMs, %zu SIGs\n\n",
           pq_registry_kem_count(reg), pq_registry_sig_count(reg));

    /* Run benchmarks */
    pq_kem_bench_result_t kem_results[32];
    pq_hybrid_bench_result_t hybrid_results[32];
    pq_sig_bench_result_t sig_results[32];
    size_t kem_count = 0, hybrid_count = 0, sig_count = 0;

    if (specific_alg) {
        /* Benchmark specific algorithm */
        const pq_kem_provider_t *kem = pq_registry_find_kem(reg, specific_alg);
        if (kem) {
            printf("Benchmarking KEM: %s\n", specific_alg);
            if (pq_bench_kem(kem, &cfg, &kem_results[0]) == PQ_SUCCESS)
                kem_count = 1;
        }
        const pq_sig_provider_t *sig = pq_registry_find_sig(reg, specific_alg);
        if (sig) {
            printf("Benchmarking SIG: %s\n", specific_alg);
            if (pq_bench_sig(sig, &cfg, &sig_results[0]) == PQ_SUCCESS)
                sig_count = 1;
        }
        const pq_hybrid_kem_t *hybrid = pq_registry_find_hybrid(reg, specific_alg);
        if (hybrid) {
            printf("Benchmarking Hybrid: %s\n", specific_alg);
            if (pq_bench_hybrid(hybrid, &cfg, &hybrid_results[0]) == PQ_SUCCESS)
                hybrid_count = 1;
        }
        if (!kem && !sig && !hybrid) {
            fprintf(stderr, "Algorithm '%s' not found in registry\n", specific_alg);
            pq_registry_destroy(reg);
            return 1;
        }
    } else {
        /* Benchmark everything */
        printf("[KEM Algorithms]\n");
        kem_count = pq_bench_all_kems(reg, &cfg, kem_results, 32);

        printf("[Hybrid Algorithms]\n");
        hybrid_count = pq_bench_all_hybrids(reg, &cfg, hybrid_results, 32);

        printf("[Signature Algorithms]\n");
        const pq_sig_provider_t *sig_provs[32];
        size_t nsigs = pq_registry_list_sigs(reg, sig_provs, 32);
        for (size_t i = 0; i < nsigs && sig_count < 32; i++) {
            if (cfg.verbose)
                fprintf(stderr, "[bench] SIG: %s...\n", sig_provs[i]->name());
            if (pq_bench_sig(sig_provs[i], &cfg, &sig_results[sig_count]) == PQ_SUCCESS)
                sig_count++;
        }
    }

    /* Print results */
    if (kem_count > 0)
        pq_bench_print_kem_results(kem_results, kem_count);
    if (hybrid_count > 0)
        pq_bench_print_hybrid_results(hybrid_results, hybrid_count);

    if (sig_count > 0) {
        printf("\n%-16s %5s  %10s %10s %10s  %6s\n",
               "Algorithm", "NIST", "kg(us)", "sign(us)", "verify(us)", "sig(B)");
        printf("%-16s %5s  %10s %10s %10s  %6s\n",
               "----------------", "-----",
               "----------", "----------", "----------", "------");
        for (size_t i = 0; i < sig_count; i++) {
            printf("%-16s %5d  %10.2f %10.2f %10.2f  %6zu\n",
                   sig_results[i].algorithm_name, sig_results[i].nist_level,
                   sig_results[i].keygen.mean_us, sig_results[i].sign.mean_us,
                   sig_results[i].verify.mean_us, sig_results[i].sig_bytes);
        }
    }

    /* Export */
    if (csv_file) {
        pq_bench_export_csv(csv_file, kem_results, kem_count,
                            hybrid_results, hybrid_count);
        printf("\nCSV exported to: %s\n", csv_file);
    }
    if (json_file) {
        pq_bench_export_json(json_file, kem_results, kem_count,
                             hybrid_results, hybrid_count);
        printf("JSON exported to: %s\n", json_file);
    }

    pq_registry_destroy(reg);
    printf("\nDone.\n");
    return 0;
}
