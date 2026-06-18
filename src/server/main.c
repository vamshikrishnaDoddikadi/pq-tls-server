/**
 * @file main.c
 * @brief PQ-TLS Server — All-in-one Post-Quantum TLS Reverse Proxy
 *
 * @author Vamshi Krishna Doddikadi
 */

#include "../core/server_config.h"
#include "../core/connection_manager.h"
#include "../benchmark/bench.h"
#include "../benchmark/bench_agility.h"
#include "../common/crypto_registry.h"
#include "../common/hybrid_combiner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/resource.h>

extern char **environ;

#define PQ_TLS_SERVER_VERSION "2.0.0"

static pq_conn_manager_t *g_manager = NULL;

/* ======================================================================== */
/* Signal handling (async-signal-safe: only set flags)                      */
/* ======================================================================== */

static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_reload   = 0;

static void shutdown_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
    /*
     * pq_conn_manager_stop() calls shutdown() on the listen fd which IS
     * async-signal-safe per POSIX. However, calling atomic_store inside
     * it is technically not guaranteed safe. To be fully correct, we only
     * set our flag and let the watcher thread handle the actual stop.
     */
}

static void reload_handler(int sig) {
    (void)sig;
    g_reload = 1;
}

static void setup_signals(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shutdown_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* SIGHUP triggers certificate reload */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = reload_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &sa, NULL);

    /* Ignore SIGPIPE using sigaction (not signal()) for portability and consistency.
     * Handle send errors via return values. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);
}

static void setup_resource_limits(void) {
    /* Ensure RLIMIT_NOFILE is set high enough for many connections. */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t desired = 65536;  /* Reasonable limit for high-concurrency scenarios */
        if (rl.rlim_cur < desired) {
            rl.rlim_cur = desired;
            if (rl.rlim_max < desired) {
                rl.rlim_max = desired;
            }
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
                fprintf(stderr, "Warning: Could not set RLIMIT_NOFILE to %lu. "
                        "Current soft limit: %lu\n",
                        desired, (unsigned long)rl.rlim_cur);
            }
        }
    }
}

/* ======================================================================== */
/* Signal watcher thread — polls flags, performs non-async-safe actions     */
/* ======================================================================== */

static void* signal_watcher_thread(void *arg) {
    pq_conn_manager_t *mgr = (pq_conn_manager_t*)arg;

    while (!g_shutdown) {
        if (g_reload) {
            g_reload = 0;
            pq_conn_manager_reload(mgr);
        }
        usleep(500000); /* Check every 500ms */
    }

    /* Shutdown was requested — perform the actual stop from this
     * non-signal context where it's safe to call any function. */
    pq_conn_manager_stop(mgr);
    return NULL;
}

/* ======================================================================== */
/* Help text                                                                */
/* ======================================================================== */

static void print_banner(void) {
    printf("\n"
           "  ╔═══════════════════════════════════════════════════╗\n"
           "  ║        PQ-TLS Server v%s                      ║\n"
           "  ║   Post-Quantum TLS Termination Reverse Proxy      ║\n"
           "  ║                                                    ║\n"
           "  ║   Key Exchange: X25519 + ML-KEM-768 (Kyber)       ║\n"
           "  ║   Protocol:     TLS 1.3                            ║\n"
           "  ╚═══════════════════════════════════════════════════╝\n\n",
           PQ_TLS_SERVER_VERSION);
}

static void print_help(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("       %s benchmark [--iterations N] [--format table|json|csv]\n", prog);
    printf("       %s agility [-n N] [-w N] [-o file.csv] [-j file.json] [-v]\n\n", prog);
    printf("Options:\n");
    printf("  -f, --config FILE    Configuration file (INI format)\n");
    printf("  -p, --port PORT      Listen port (default: 8443)\n");
    printf("  -c, --cert FILE      TLS certificate file (PEM)\n");
    printf("  -k, --key FILE       TLS private key file (PEM)\n");
    printf("  -a, --ca FILE        CA certificate for client auth\n");
    printf("  -b, --backend ADDR   Upstream backend (host:port, repeatable)\n");
    printf("                       Supports: host:port, tls://host:port,\n");
    printf("                       unix:/path/to/sock, host:port;weight=N\n");
    printf("  -g, --groups LIST    TLS key exchange groups\n");
    printf("                       (default: X25519MLKEM768:X25519)\n");
    printf("  -Q, --require-pq     Require post-quantum key exchange\n");
    printf("  -w, --workers N      Worker threads (0 = auto)\n");
    printf("  -l, --log FILE       Log file (default: stderr)\n");
    printf("  -j, --json-log       Enable structured JSON logging\n");
    printf("  -v, --verbose        Enable debug logging\n");
    printf("  -d, --daemon         Run as daemon\n");
    printf("  -H, --health-port N  Dashboard/metrics HTTP port (0 = off)\n");
    printf("  -R, --rate-limit N   Max connections per second per IP\n");
    printf("  -S, --session-cache  TLS session cache size (default: 20000)\n");
    printf("  -h, --help           Show this help\n");
    printf("\nBenchmark:\n");
    printf("  %s benchmark [--iterations 1000] [--format table]\n", prog);
    printf("  Runs PQ algorithm benchmarks (ML-KEM, ML-DSA, Ed25519)\n\n");
    printf("  %s agility [-n 1000] [-w 100] [-o results.csv] [-j results.json]\n", prog);
    printf("  Crypto-agility benchmark across ALL registry providers incl. hybrids\n");
    printf("\nSignals:\n");
    printf("  SIGHUP   Reload TLS certificates without dropping connections\n");
    printf("  SIGINT   Graceful shutdown\n");
    printf("  SIGTERM  Graceful shutdown\n");
    printf("\nExamples:\n");
    printf("  %s -c cert.pem -k key.pem -b 127.0.0.1:8080\n", prog);
    printf("  %s -c cert.pem -k key.pem -b 127.0.0.1:8080 -H 9090 -R 50 --json-log\n", prog);
    printf("  %s --config /etc/pq-tls-server.conf\n\n", prog);
}

/* ======================================================================== */
/* Benchmark subcommand                                                     */
/* ======================================================================== */


/* ======================================================================== */
/* Agility benchmark subcommand (registry-wide, includes hybrids)            */
/* ======================================================================== */

static int run_agility(int argc, char **argv) {
    pq_bench_config_t cfg;
    pq_bench_config_default(&cfg);
    char csv_file[512] = {0};
    char json_file[512] = {0};

    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--iterations") == 0)
            && i + 1 < argc) {
            { long v = strtol(argv[++i], NULL, 10); if (v > 0) cfg.iterations = (int)v; }
            if (cfg.iterations <= 0) cfg.iterations = 1000;
        }
        else if ((strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--warmup") == 0)
            && i + 1 < argc) {
            { long v = strtol(argv[++i], NULL, 10); if (v >= 0) cfg.warmup_iterations = (int)v; }
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            cfg.verbose = 1;
        }
        else if ((strcmp(argv[i], "-o") == 0) && i + 1 < argc) {
            snprintf(csv_file, sizeof(csv_file), "%s", argv[++i]);
        }
        else if ((strcmp(argv[i], "-j") == 0) && i + 1 < argc) {
            snprintf(json_file, sizeof(json_file), "%s", argv[++i]);
        }
    }

    print_banner();

    /* Initialize registry and load builtins + any plugins */
    pq_registry_t *reg = pq_registry_create();
    if (!reg) {
        fprintf(stderr, "Failed to create algorithm registry\n");
        return 1;
    }
    pq_registry_register_builtins(reg);

    /* Allocate result arrays */
    pq_kem_bench_result_t *kem_results =
        calloc(PQ_REGISTRY_MAX_KEM_PROVIDERS, sizeof(pq_kem_bench_result_t));
    pq_hybrid_bench_result_t *hybrid_results =
        calloc(PQ_REGISTRY_MAX_HYBRID_KEMS, sizeof(pq_hybrid_bench_result_t));

    if (!kem_results || !hybrid_results) {
        fprintf(stderr, "Out of memory\n");
        pq_registry_destroy(reg);
        free(kem_results);
        free(hybrid_results);
        return 1;
    }

    printf("\n=== Crypto-Agility Benchmark Suite ===\n");
    printf("Iterations: %d  Warmup: %d\n\n", cfg.iterations, cfg.warmup_iterations);

    /* Benchmark all KEM providers */
    size_t kem_count = pq_bench_all_kems(reg, &cfg, kem_results, PQ_REGISTRY_MAX_KEM_PROVIDERS);
    if (kem_count > 0) {
        pq_bench_print_kem_results(kem_results, kem_count);
    } else {
        printf("No KEM providers found in registry.\n");
    }

    /* Benchmark all hybrid KEM pairs */
    size_t hybrid_count = pq_bench_all_hybrids(reg, &cfg, hybrid_results,
                                                PQ_REGISTRY_MAX_HYBRID_KEMS);
    if (hybrid_count > 0) {
        printf("\n");
        pq_bench_print_hybrid_results(hybrid_results, hybrid_count);
    } else {
        printf("\nNo hybrid KEM pairs found.\n");
    }

    /* Export if requested */
    if (csv_file[0]) {
        if (pq_bench_export_csv(csv_file, kem_results, kem_count,
                                hybrid_results, hybrid_count) == 0) {
            printf("\nResults exported to: %s\n", csv_file);
        }
    }
    if (json_file[0]) {
        if (pq_bench_export_json(json_file, kem_results, kem_count,
                                 hybrid_results, hybrid_count) == 0) {
            printf("Results exported to: %s\n", json_file);
        }
    }

    free(kem_results);
    free(hybrid_results);
    pq_registry_destroy(reg);
    return 0;
}

static int run_benchmark(int argc, char **argv) {
    int iterations = 1000;
    pq_bench_format_t format = PQ_BENCH_FORMAT_TABLE;

    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "--iterations") == 0 || strcmp(argv[i], "-n") == 0)
            && i + 1 < argc) {
            { long v = strtol(argv[++i], NULL, 10); if (v > 0) iterations = (int)v; }
            if (iterations <= 0) iterations = 1000;
        }
        else if ((strcmp(argv[i], "--format") == 0) && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "json") == 0) format = PQ_BENCH_FORMAT_JSON;
            else if (strcmp(argv[i], "csv") == 0) format = PQ_BENCH_FORMAT_CSV;
        }
    }

    print_banner();
    return pq_bench_run(iterations, format);
}

/* ======================================================================== */
/* Daemonize                                                                */
/* ======================================================================== */

static void daemonize_process(const char *pid_file) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0); /* parent exits */

    setsid();
    umask(0);
    if (chdir("/") != 0) {
        perror("chdir");
    }

    /* Redirect stdin/stdout/stderr to /dev/null (not just close them).
     * Closing fd 0-2 causes newly opened fds to take those numbers,
     * and any library writing to stderr would crash with EBADF. */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO)
            close(devnull);
    }

    /* Close all inherited file descriptors above stderr to prevent leaks.
     * Keep 0-2 (stdin/stdout/stderr) as they are now pointing to /dev/null. */
    int max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 1024) max_fd = 1024;
    if (max_fd > 65536) max_fd = 65536;  /* Limit to prevent excessive loops */
    for (int fd = 3; fd < max_fd; fd++) {
        int flags = fcntl(fd, F_GETFD);
        if (flags != -1) close(fd);
    }

    /* Write PID file */
    if (pid_file && pid_file[0]) {
        FILE *fp = fopen(pid_file, "w");
        if (fp) {
            fprintf(fp, "%d\n", getpid());
            fclose(fp);
        }
    }
}

/* ======================================================================== */
/* Main                                                                     */
/* ======================================================================== */

int main(int argc, char **argv) {
    /* Check for subcommands */
    if (argc >= 2 && strcmp(argv[1], "benchmark") == 0) {
        return run_benchmark(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "agility") == 0) {
        return run_agility(argc, argv);
    }

    pq_server_config_t config;
    pq_server_config_defaults(&config);

    /* First pass: find --config/-f to load config file first */
    int config_loaded = 0;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--config") == 0)
            && i + 1 < argc) {
            if (pq_server_config_load(&config, argv[i + 1]) != 0) {
                return 1;
            }
            snprintf(config.config_file_path, sizeof(config.config_file_path), "%s", argv[i + 1]);
            config_loaded = 1;
            break;
        }
    }
    /* Auto-load default config if none specified */
    if (!config_loaded) {
        pq_server_config_load(&config, "/etc/pq-tls-server.conf");
        snprintf(config.config_file_path, sizeof(config.config_file_path),
                 "/etc/pq-tls-server.conf");
    }

    /* Second pass: CLI args override config file */
    int ret = pq_server_config_parse_args(&config, argc, argv);
    if (ret > 0) {
        print_banner();
        print_help(argv[0]);
        return 0;
    }
    if (ret < 0) {
        fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
        return 1;
    }

    /* Validate */
    if (pq_server_config_validate(&config) != 0) {
        return 1;
    }

    /* Print banner (before daemonizing) */
    if (!config.daemonize) {
        print_banner();
        if (config.verbose) {
            pq_server_config_print(&config);
        }
    }

    /* Daemonize if requested */
    if (config.daemonize) {
        daemonize_process(config.pid_file);
    }

    setup_signals();
    setup_resource_limits();

    /* Create connection manager */
    g_manager = pq_conn_manager_create(&config);
    if (!g_manager) {
        fprintf(stderr, "Failed to initialize server\n");
        return 1;
    }

    /* Start signal watcher thread — handles SIGHUP reload and shutdown
     * from a non-signal context where it's safe to call any function. */
    pthread_t sig_tid;
    if (pthread_create(&sig_tid, NULL, signal_watcher_thread, g_manager) != 0) {
        fprintf(stderr, "Failed to create signal watcher thread\n");
        pq_conn_manager_destroy(g_manager);
        return 1;
    }
    pthread_detach(sig_tid);

    if (!config.daemonize) {
        printf("Server ready. Press Ctrl+C to stop.\n");
        printf("Send SIGHUP to reload certificates.\n\n");
    }

    /* Run server (blocks until stopped) */
    pq_conn_manager_run(g_manager);

    /* Check if restart was requested by management UI */
    int do_restart = (atomic_load(&g_manager->restart_pending) == 2);

    /* Cleanup */
    pq_conn_manager_destroy(g_manager);
    g_manager = NULL;

    if (do_restart) {
        if (!config.daemonize) {
            printf("\nServer restarting...\n");
        }
        /* Re-exec ourselves to restart with same arguments */
        execve("/proc/self/exe", argv, environ);
        /* execve only returns on error */
        perror("execve failed during restart");
        return 1;
    }

    if (!config.daemonize) {
        printf("\nServer stopped.\n");
    }

    /* Remove PID file */
    if (config.pid_file[0]) {
        unlink(config.pid_file);
    }

    return 0;
}
