/**
 * @file tls_server_pq.c
 * @brief Post-Quantum TLS 1.3 Server Implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 */

#include "tls_server_pq.h"
#include "../common/pq_utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <limits.h>
#include <libgen.h>

/**
 * PQ TLS Server structure
 */
typedef struct pq_server {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int listen_fd;
    int client_fd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    /* Performance metrics */
    struct timespec start_time;
    struct timespec end_time;
    double handshake_duration;

    /* Logging */
    FILE *log_file;
    int verbose;

    /* CA management */
    char *ca_file;
    int require_client_auth;

    /* Providers */
    OSSL_PROVIDER *oqs_provider;
    OSSL_PROVIDER *default_provider;
} pq_server_t;

/**
 * Auto-detect and set OPENSSL_MODULES to find oqsprovider.so.
 * Searches relative to the binary location in multiple candidate dirs.
 */
static void setup_oqs_provider_path(void) {
    /* If already set and contains oqsprovider.so, skip */
    const char *existing = getenv("OPENSSL_MODULES");
    if (existing) {
        char check[PATH_MAX];
        snprintf(check, sizeof(check), "%s/oqsprovider.so", existing);
        if (access(check, R_OK) == 0) return;
    }

    /* Resolve binary location via /proc/self/exe */
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) return;
    exe_path[len] = '\0';

    /* Binary is at <root>/build/bin/tls_server_pq => go up 3 levels */
    char exe_copy1[PATH_MAX], exe_copy2[PATH_MAX], exe_copy3[PATH_MAX];
    strncpy(exe_copy1, exe_path, PATH_MAX - 1);
    exe_copy1[PATH_MAX - 1] = '\0';
    char *bin_dir = dirname(exe_copy1);       /* build/bin */
    strncpy(exe_copy2, bin_dir, PATH_MAX - 1);
    exe_copy2[PATH_MAX - 1] = '\0';
    char *build_dir = dirname(exe_copy2);     /* build */
    strncpy(exe_copy3, build_dir, PATH_MAX - 1);
    exe_copy3[PATH_MAX - 1] = '\0';
    char *root = dirname(exe_copy3);          /* project root */

    /* Candidate directories for oqsprovider.so */
    const char *suffixes[] = {
        "/vendor/oqs-provider/build/lib",
        "/vendor/lib64/ossl-modules",
        "/vendor/openssl/lib64/ossl-modules",
        "/vendor/openssl/lib/ossl-modules",
        NULL
    };

    char path[PATH_MAX], provider[PATH_MAX];
    for (int i = 0; suffixes[i]; i++) {
        snprintf(path, sizeof(path), "%s%s", root, suffixes[i]);
        snprintf(provider, sizeof(provider), "%s/oqsprovider.so", path);
        if (access(provider, R_OK) == 0) {
            setenv("OPENSSL_MODULES", path, 1);
            return;
        }
    }
}

/**
 * Create a new PQ TLS server
 */
pq_server_t* pq_server_create(const char *cert_file, const char *key_file,
                               const char *log_file, const char *ca_file,
                               int require_client_auth, int verbose) {
    pq_server_t *server = calloc(1, sizeof(pq_server_t));
    if (!server) {
        fprintf(stderr, "Failed to allocate server structure\n");
        return NULL;
    }

    /* Initialize logging */
    if (log_file) {
        server->log_file = fopen(log_file, "w");
        if (!server->log_file) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
            free(server);
            return NULL;
        }
    }
    server->verbose = verbose;
    server->listen_fd = -1;
    server->client_fd = -1;
    server->require_client_auth = require_client_auth;

    if (server->require_client_auth && !ca_file) {
        fprintf(stderr, "CA file is required for client authentication\n");
        if (server->log_file) fclose(server->log_file);
        free(server);
        return NULL;
    }

    if (ca_file) {
        server->ca_file = pq_strdup(ca_file);
        if (!server->ca_file) {
            fprintf(stderr, "Failed to allocate CA file path\n");
            if (server->log_file) fclose(server->log_file);
            free(server);
            return NULL;
        }
    }

    /* OpenSSL 3.0+ auto-initializes; explicit calls are deprecated.
       We only need OPENSSL_init_ssl() as a no-op safety net. */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    /* Auto-detect OQS provider location */
    setup_oqs_provider_path();

    server->default_provider = OSSL_PROVIDER_load(NULL, "default");
    server->oqs_provider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!server->default_provider || !server->oqs_provider) {
        fprintf(stderr, "Failed to load OpenSSL providers\n");
        const char *mod = getenv("OPENSSL_MODULES");
        fprintf(stderr, "  OPENSSL_MODULES=%s\n", mod ? mod : "(not set)");
        fprintf(stderr, "  Hint: ensure oqsprovider.so is in OPENSSL_MODULES directory\n");
        /* SECURITY: Always unload BOTH providers to prevent leaks */
        if (server->default_provider) OSSL_PROVIDER_unload(server->default_provider);
        if (server->oqs_provider) OSSL_PROVIDER_unload(server->oqs_provider);
        if (server->log_file) fclose(server->log_file);
        free(server->ca_file);
        free(server);
        return NULL;
    }

    if (verbose) {
        const char *mod = getenv("OPENSSL_MODULES");
        fprintf(stdout, "OQS provider loaded from: %s\n", mod ? mod : "(default)");
    }

    /* Create SSL context */
    server->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!server->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        OSSL_PROVIDER_unload(server->oqs_provider);
        OSSL_PROVIDER_unload(server->default_provider);
        if (server->log_file) fclose(server->log_file);
        free(server->ca_file);
        free(server);
        return NULL;
    }

    /* Set TLS version to 1.3 */
    SSL_CTX_set_min_proto_version(server->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(server->ssl_ctx, TLS1_3_VERSION);

    /* Set Supported Groups for PQC */
    if (SSL_CTX_set1_groups_list(server->ssl_ctx, "X25519MLKEM768") != 1) {
        fprintf(stderr, "Failed to set supported groups (X25519MLKEM768)\n");
    }

    /* Load certificate and key */
    if (cert_file && key_file) {
        if (SSL_CTX_use_certificate_file(server->ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(server->ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(server->ssl_ctx);
            OSSL_PROVIDER_unload(server->oqs_provider);
            OSSL_PROVIDER_unload(server->default_provider);
            if (server->log_file) fclose(server->log_file);
            free(server->ca_file);
            free(server);
            return NULL;
        }
        if (SSL_CTX_check_private_key(server->ssl_ctx) != 1) {
            fprintf(stderr, "Server private key does not match certificate\n");
            SSL_CTX_free(server->ssl_ctx);
            OSSL_PROVIDER_unload(server->oqs_provider);
            OSSL_PROVIDER_unload(server->default_provider);
            if (server->log_file) fclose(server->log_file);
            free(server->ca_file);
            free(server);
            return NULL;
        }
    }

    if (server->ca_file) {
        if (SSL_CTX_load_verify_locations(server->ssl_ctx, server->ca_file, NULL) != 1) {
            fprintf(stderr, "Failed to load CA file: %s\n", server->ca_file);
            SSL_CTX_free(server->ssl_ctx);
            OSSL_PROVIDER_unload(server->oqs_provider);
            OSSL_PROVIDER_unload(server->default_provider);
            if (server->log_file) fclose(server->log_file);
            free(server->ca_file);
            free(server);
            return NULL;
        }
    }

    if (server->require_client_auth) {
        SSL_CTX_set_verify(server->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(server->ssl_ctx, 4);
    }

    if (server->verbose) {
        fprintf(stdout, "PQ TLS Server created successfully\n");
    }
    if (server->log_file) {
        fprintf(server->log_file, "PQ TLS Server initialized\n");
        fflush(server->log_file);
    }

    return server;
}

/**
 * Bind and listen on port
 */
int pq_server_listen(pq_server_t *server, uint16_t port) {
    if (!server) return -1;

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server->listen_fd);
        return -1;
    }

    memset(&server->server_addr, 0, sizeof(server->server_addr));
    server->server_addr.sin_family = AF_INET;
    server->server_addr.sin_addr.s_addr = INADDR_ANY;
    server->server_addr.sin_port = htons(port);

    if (bind(server->listen_fd, (struct sockaddr*)&server->server_addr,
             sizeof(server->server_addr)) < 0) {
        perror("Bind failed");
        close(server->listen_fd);
        return -1;
    }

    if (listen(server->listen_fd, 512) < 0) {
        perror("Listen failed");
        close(server->listen_fd);
        return -1;
    }

    if (server->verbose) printf("Server listening on port %u\n", port);
    if (server->log_file) {
        fprintf(server->log_file, "Server listening on port %u\n", port);
        fflush(server->log_file);
    }

    return 0;
}

/**
 * Accept client connection
 */
int pq_server_accept(pq_server_t *server) {
    if (!server) return -1;

    socklen_t addr_len = sizeof(server->client_addr);
    server->client_fd = accept(server->listen_fd,
                              (struct sockaddr*)&server->client_addr,
                              &addr_len);
    if (server->client_fd < 0) {
        perror("Accept failed");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &server->start_time);

    server->ssl = SSL_new(server->ssl_ctx);
    if (!server->ssl) {
        ERR_print_errors_fp(stderr);
        close(server->client_fd);
        return -1;
    }

    SSL_set_fd(server->ssl, server->client_fd);

    if (SSL_accept(server->ssl) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(server->ssl);
        close(server->client_fd);
        return -1;
    }

    /* Log negotiated protocol and cipher */
    printf("\n===============================================================\n");
    printf("TLS Handshake Complete\n");
    printf("===============================================================\n");
    printf("Protocol: %s\n", SSL_get_version(server->ssl));
    printf("Cipher: %s\n", SSL_get_cipher(server->ssl));

    int group_nid = SSL_get_negotiated_group(server->ssl);
    if (group_nid != NID_undef) {
        const char *group_name = SSL_group_to_name(server->ssl, group_nid);
        printf("Key Exchange Group: %s (NID: %d)\n",
               group_name ? group_name : "unknown", group_nid);
        if (group_name && (strstr(group_name, "MLKEM") || strstr(group_name, "mlkem"))) {
            printf("\n  POST-QUANTUM KEY EXCHANGE ACTIVE!\n");
            printf("   Algorithm: %s\n", group_name);
            printf("   Security: Quantum-Resistant\n");
        } else {
            printf("  Classical key exchange (no PQ)\n");
        }
    } else {
        printf("  Could not determine key exchange group\n");
    }
    printf("===============================================================\n\n");

    if (server->require_client_auth) {
        long verify_result = SSL_get_verify_result(server->ssl);
        if (verify_result != X509_V_OK) {
            fprintf(stderr, "Client certificate verification failed: %s\n",
                    X509_verify_cert_error_string(verify_result));
            SSL_free(server->ssl);
            close(server->client_fd);
            return -1;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &server->end_time);
    server->handshake_duration = (server->end_time.tv_sec - server->start_time.tv_sec) * 1000.0 +
                                 (server->end_time.tv_nsec - server->start_time.tv_nsec) / 1000000.0;

    if (server->verbose) {
        printf("Client connected from %s:%u\n",
               inet_ntoa(server->client_addr.sin_addr),
               ntohs(server->client_addr.sin_port));
        printf("TLS handshake completed in %.2f ms\n", server->handshake_duration);
    }
    if (server->log_file) {
        fprintf(server->log_file, "Client connected\n");
        fprintf(server->log_file, "Handshake completed in %.2f ms\n", server->handshake_duration);
        fflush(server->log_file);
    }

    return 0;
}

/**
 * Send data to client
 */
int pq_server_send(pq_server_t *server, const uint8_t *data, size_t len) {
    if (!server || !data) return -1;

    int sent = SSL_write(server->ssl, data, len);
    if (sent <= 0) {
        int err = SSL_get_error(server->ssl, sent);
        fprintf(stderr, "SSL_write failed with error %d\n", err);
        return -1;
    }

    if (server->verbose) printf("Sent %d bytes to client\n", sent);
    return sent;
}

/**
 * Receive data from client
 */
int pq_server_recv(pq_server_t *server, uint8_t *buf, size_t buf_len) {
    if (!server || !buf) return -1;

    int received = SSL_read(server->ssl, buf, buf_len);
    if (received < 0) {
        int err = SSL_get_error(server->ssl, received);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "SSL_read failed with error %d\n", err);
        }
        return -1;
    }

    if (server->verbose && received > 0) printf("Received %d bytes from client\n", received);
    return received;
}

/**
 * Get performance metrics
 */
void pq_server_get_metrics(pq_server_t *server, double *duration) {
    if (!server) return;
    if (duration) *duration = server->handshake_duration;
}

/**
 * Clean up and destroy server
 */
void pq_server_destroy(pq_server_t *server) {
    if (!server) return;

    if (server->ssl) {
        SSL_shutdown(server->ssl);
        SSL_free(server->ssl);
    }
    if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
    if (server->oqs_provider) OSSL_PROVIDER_unload(server->oqs_provider);
    if (server->default_provider) OSSL_PROVIDER_unload(server->default_provider);

    if (server->client_fd >= 0) close(server->client_fd);
    if (server->listen_fd >= 0) close(server->listen_fd);

    if (server->log_file) {
        fprintf(server->log_file, "Server destroyed\n");
        fclose(server->log_file);
    }

    free(server->ca_file);
    free(server);
}
