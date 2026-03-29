/**
 * @file pq_config.c
 * @brief Post-Quantum TLS Configuration Management Implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 */

#include "pq_config.h"
#include "pq_kem.h"
#include "pq_sig.h"
#include "hpke.h"
#include "hybrid_kex.h"
#include "pq_errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/crypto.h>

/* ========================================================================
 * TLS Version Constants
 * ======================================================================== */

#define TLS_VERSION_1_2  0x0303
#define TLS_VERSION_1_3  0x0304

/* ========================================================================
 * Helper Functions
 * ======================================================================== */

/**
 * @brief Trim whitespace from string in-place
 */
static void trim_whitespace(char *str) {
    if (!str) return;
    
    /* Trim leading whitespace */
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    /* Handle empty string after leading trim */
    if (*start == '\0') {
        str[0] = '\0';
        return;
    }

    /* Trim trailing whitespace */
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';
    
    /* Move trimmed string to beginning */
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

/**
 * @brief Parse boolean value from string
 */
static int parse_bool(const char *value) {
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 || 
        strcmp(value, "yes") == 0 || strcmp(value, "on") == 0) {
        return 1;
    }
    return 0;
}

/**
 * @brief Convert boolean to string
 */
static const char* bool_to_string(int value) {
    return value ? "true" : "false";
}

/* ========================================================================
 * Configuration Management Functions
 * ======================================================================== */

pq_config_t* pq_config_init(void) {
    pq_config_t *config = (pq_config_t*)malloc(sizeof(pq_config_t));
    if (!config) {
        return NULL;
    }
    
    /* Initialize with secure defaults */
    
    /* KEM configuration - ML-KEM-768 for balanced security/performance */
    config->default_kem_algorithm = PQ_KEM_MLKEM768;
    config->enable_classical_kem = 1;  /* Allow fallback for compatibility */
    config->enable_hybrid_kem = 1;     /* Enable hybrid mode */
    
    /* Signature configuration - ML-DSA-65 for NIST Level 3 */
    config->default_sig_algorithm = PQ_SIG_MLDSA65;
    config->enable_classical_sig = 1;  /* Allow fallback for compatibility */
    
    /* TLS configuration - Support TLS 1.2 and 1.3 */
    config->tls_min_version = TLS_VERSION_1_2;
    config->tls_max_version = TLS_VERSION_1_3;
    config->enable_pq_only_mode = 0;   /* Allow classical algorithms */
    
    /* HPKE configuration - X25519+ML-KEM-768 hybrid with AES-256-GCM */
    config->default_hpke_kem = HPKE_KEM_X25519_MLKEM768_CONCAT;
    config->default_hpke_aead = HPKE_AEAD_AES256GCM;
    
    /* Hybrid KEX configuration - CONCAT mode with X25519 */
    config->default_hybrid_mode = HYBRID_MODE_CONCAT;
    config->default_classical_kex = HYBRID_CLASSICAL_X25519;
    
    /* Performance tuning - Enable constant-time operations */
    config->enable_constant_time = 1;
    config->enable_memory_lock = 0;    /* Disabled by default (requires privileges) */
    
    /* Logging and debugging - Warnings only */
    config->log_level = 2;             /* 2 = warnings */
    config->enable_benchmarking = 0;
    
    return config;
}

void pq_config_free(pq_config_t *config) {
    if (config) {
        /* Clear sensitive data before freeing - use OPENSSL_cleanse to prevent
         * compiler from optimizing away the clear of sensitive config fields */
        OPENSSL_cleanse(config, sizeof(pq_config_t));
        free(config);
    }
}

int pq_config_set_kem(pq_config_t *config, int algorithm) {
    if (!config) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Validate algorithm */
    if (algorithm != PQ_KEM_MLKEM512 && 
        algorithm != PQ_KEM_MLKEM768 && 
        algorithm != PQ_KEM_MLKEM1024) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    config->default_kem_algorithm = algorithm;
    return PQ_SUCCESS;
}

int pq_config_set_sig(pq_config_t *config, int algorithm) {
    if (!config) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Validate algorithm */
    if (algorithm != PQ_SIG_MLDSA44 && 
        algorithm != PQ_SIG_MLDSA65 && 
        algorithm != PQ_SIG_MLDSA87) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    config->default_sig_algorithm = algorithm;
    return PQ_SUCCESS;
}

int pq_config_set_tls_version(pq_config_t *config, int min, int max) {
    if (!config) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Validate version range */
    if (min > max) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    /* Validate version values */
    if ((min != TLS_VERSION_1_2 && min != TLS_VERSION_1_3) ||
        (max != TLS_VERSION_1_2 && max != TLS_VERSION_1_3)) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    config->tls_min_version = min;
    config->tls_max_version = max;
    return PQ_SUCCESS;
}

int pq_config_get_kem(const pq_config_t *config) {
    if (!config) {
        return -1;
    }
    return config->default_kem_algorithm;
}

int pq_config_get_sig(const pq_config_t *config) {
    if (!config) {
        return -1;
    }
    return config->default_sig_algorithm;
}

int pq_config_validate(const pq_config_t *config) {
    if (!config) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Validate KEM algorithm */
    if (config->default_kem_algorithm != PQ_KEM_MLKEM512 &&
        config->default_kem_algorithm != PQ_KEM_MLKEM768 &&
        config->default_kem_algorithm != PQ_KEM_MLKEM1024) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Validate signature algorithm */
    if (config->default_sig_algorithm != PQ_SIG_MLDSA44 &&
        config->default_sig_algorithm != PQ_SIG_MLDSA65 &&
        config->default_sig_algorithm != PQ_SIG_MLDSA87 &&
        config->default_sig_algorithm != PQ_SIG_ED25519 &&
        config->default_sig_algorithm != PQ_SIG_ECDSA_P256 &&
        config->default_sig_algorithm != PQ_SIG_RSA2048) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Validate TLS versions */
    if (config->tls_min_version > config->tls_max_version) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    if ((config->tls_min_version != TLS_VERSION_1_2 && 
         config->tls_min_version != TLS_VERSION_1_3) ||
        (config->tls_max_version != TLS_VERSION_1_2 && 
         config->tls_max_version != TLS_VERSION_1_3)) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    /* Validate HPKE KEM */
    if (config->default_hpke_kem != HPKE_KEM_X25519 &&
        config->default_hpke_kem != HPKE_KEM_MLKEM768 &&
        config->default_hpke_kem != HPKE_KEM_X25519_MLKEM768_CONCAT) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Validate HPKE AEAD */
    if (config->default_hpke_aead != HPKE_AEAD_AES256GCM &&
        config->default_hpke_aead != HPKE_AEAD_CHACHAPOLY) {
        return PQ_ERR_INVALID_ALGORITHM;
    }
    
    /* Validate hybrid mode */
    if (config->default_hybrid_mode != HYBRID_MODE_CONCAT &&
        config->default_hybrid_mode != HYBRID_MODE_XOR) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    /* Validate classical KEX */
    if (config->default_classical_kex != HYBRID_CLASSICAL_X25519 &&
        config->default_classical_kex != HYBRID_CLASSICAL_P256) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    /* Validate log level */
    if (config->log_level < 0 || config->log_level > 4) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    /* Check for conflicting options */
    if (config->enable_pq_only_mode && 
        (config->enable_classical_kem || config->enable_classical_sig)) {
        return PQ_ERR_CONFIG_INVALID;
    }
    
    return PQ_SUCCESS;
}

int pq_config_load(pq_config_t *config, const char *filename) {
    if (!config || !filename) {
        return PQ_ERR_NULL_POINTER;
    }
    
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return PQ_ERR_CONFIG_LOAD_FAILED;
    }
    
    char line[256];
    char section[64] = "";
    
    while (fgets(line, sizeof(line), fp)) {
        /* Remove newline */
        line[strcspn(line, "\r\n")] = '\0';
        
        /* Trim whitespace */
        trim_whitespace(line);
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') {
            continue;
        }
        
        /* Parse section headers [section] */
        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (end) {
                *end = '\0';
                strncpy(section, line + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = '\0';
                trim_whitespace(section);
            }
            continue;
        }
        
        /* Parse key=value pairs */
        char *equals = strchr(line, '=');
        if (!equals) {
            continue;
        }
        
        *equals = '\0';
        char *key = line;
        char *value = equals + 1;
        
        trim_whitespace(key);
        trim_whitespace(value);
        
        /* Parse based on section and key */
        if (strcmp(section, "kem") == 0) {
            if (strcmp(key, "default_algorithm") == 0) {
                if (strcmp(value, "MLKEM512") == 0) {
                    config->default_kem_algorithm = PQ_KEM_MLKEM512;
                } else if (strcmp(value, "MLKEM768") == 0) {
                    config->default_kem_algorithm = PQ_KEM_MLKEM768;
                } else if (strcmp(value, "MLKEM1024") == 0) {
                    config->default_kem_algorithm = PQ_KEM_MLKEM1024;
                }
            } else if (strcmp(key, "enable_classical") == 0) {
                config->enable_classical_kem = parse_bool(value);
            } else if (strcmp(key, "enable_hybrid") == 0) {
                config->enable_hybrid_kem = parse_bool(value);
            }
        } else if (strcmp(section, "signature") == 0) {
            if (strcmp(key, "default_algorithm") == 0) {
                if (strcmp(value, "MLDSA44") == 0) {
                    config->default_sig_algorithm = PQ_SIG_MLDSA44;
                } else if (strcmp(value, "MLDSA65") == 0) {
                    config->default_sig_algorithm = PQ_SIG_MLDSA65;
                } else if (strcmp(value, "MLDSA87") == 0) {
                    config->default_sig_algorithm = PQ_SIG_MLDSA87;
                }
            } else if (strcmp(key, "enable_classical") == 0) {
                config->enable_classical_sig = parse_bool(value);
            }
        } else if (strcmp(section, "tls") == 0) {
            if (strcmp(key, "min_version") == 0) {
                if (strcmp(value, "1.2") == 0) {
                    config->tls_min_version = TLS_VERSION_1_2;
                } else if (strcmp(value, "1.3") == 0) {
                    config->tls_min_version = TLS_VERSION_1_3;
                }
            } else if (strcmp(key, "max_version") == 0) {
                if (strcmp(value, "1.2") == 0) {
                    config->tls_max_version = TLS_VERSION_1_2;
                } else if (strcmp(value, "1.3") == 0) {
                    config->tls_max_version = TLS_VERSION_1_3;
                }
            } else if (strcmp(key, "pq_only_mode") == 0) {
                config->enable_pq_only_mode = parse_bool(value);
            }
        } else if (strcmp(section, "hpke") == 0) {
            if (strcmp(key, "default_kem") == 0) {
                if (strcmp(value, "X25519") == 0) {
                    config->default_hpke_kem = HPKE_KEM_X25519;
                } else if (strcmp(value, "MLKEM768") == 0) {
                    config->default_hpke_kem = HPKE_KEM_MLKEM768;
                } else if (strcmp(value, "X25519_MLKEM768_CONCAT") == 0) {
                    config->default_hpke_kem = HPKE_KEM_X25519_MLKEM768_CONCAT;
                }
            } else if (strcmp(key, "default_aead") == 0) {
                if (strcmp(value, "AES256GCM") == 0) {
                    config->default_hpke_aead = HPKE_AEAD_AES256GCM;
                } else if (strcmp(value, "CHACHA20POLY1305") == 0) {
                    config->default_hpke_aead = HPKE_AEAD_CHACHAPOLY;
                }
            }
        } else if (strcmp(section, "hybrid_kex") == 0) {
            if (strcmp(key, "default_mode") == 0) {
                if (strcmp(value, "CONCAT") == 0) {
                    config->default_hybrid_mode = HYBRID_MODE_CONCAT;
                } else if (strcmp(value, "XOR") == 0) {
                    config->default_hybrid_mode = HYBRID_MODE_XOR;
                }
            } else if (strcmp(key, "default_classical") == 0) {
                if (strcmp(value, "X25519") == 0) {
                    config->default_classical_kex = HYBRID_CLASSICAL_X25519;
                } else if (strcmp(value, "P256") == 0) {
                    config->default_classical_kex = HYBRID_CLASSICAL_P256;
                }
            }
        } else if (strcmp(section, "performance") == 0) {
            if (strcmp(key, "constant_time") == 0) {
                config->enable_constant_time = parse_bool(value);
            } else if (strcmp(key, "memory_lock") == 0) {
                config->enable_memory_lock = parse_bool(value);
            }
        } else if (strcmp(section, "logging") == 0) {
            if (strcmp(key, "log_level") == 0) {
                if (strcmp(value, "none") == 0) {
                    config->log_level = 0;
                } else if (strcmp(value, "error") == 0) {
                    config->log_level = 1;
                } else if (strcmp(value, "warn") == 0) {
                    config->log_level = 2;
                } else if (strcmp(value, "info") == 0) {
                    config->log_level = 3;
                } else if (strcmp(value, "debug") == 0) {
                    config->log_level = 4;
                }
            } else if (strcmp(key, "enable_benchmarking") == 0) {
                config->enable_benchmarking = parse_bool(value);
            }
        }
    }
    
    fclose(fp);
    return pq_config_validate(config);
}

int pq_config_save(const pq_config_t *config, const char *filename) {
    if (!config || !filename) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Validate configuration before saving */
    int ret = pq_config_validate(config);
    if (ret != PQ_SUCCESS) {
        return ret;
    }
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return PQ_ERR_CONFIG_SAVE_FAILED;
    }
    
    /* Write header comment */
    fprintf(fp, "# Post-Quantum TLS Configuration File\n");
    fprintf(fp, "# Generated: 2026-01-22\n");
    fprintf(fp, "# Format: INI-style with sections and key=value pairs\n\n");
    
    /* KEM section */
    fprintf(fp, "[kem]\n");
    fprintf(fp, "# Default KEM algorithm: MLKEM512, MLKEM768, MLKEM1024\n");
    fprintf(fp, "default_algorithm=");
    if (config->default_kem_algorithm == PQ_KEM_MLKEM512) {
        fprintf(fp, "MLKEM512\n");
    } else if (config->default_kem_algorithm == PQ_KEM_MLKEM768) {
        fprintf(fp, "MLKEM768\n");
    } else if (config->default_kem_algorithm == PQ_KEM_MLKEM1024) {
        fprintf(fp, "MLKEM1024\n");
    }
    fprintf(fp, "# Allow classical KEM fallback (X25519)\n");
    fprintf(fp, "enable_classical=%s\n", bool_to_string(config->enable_classical_kem));
    fprintf(fp, "# Enable hybrid KEM mode\n");
    fprintf(fp, "enable_hybrid=%s\n\n", bool_to_string(config->enable_hybrid_kem));
    
    /* Signature section */
    fprintf(fp, "[signature]\n");
    fprintf(fp, "# Default signature algorithm: MLDSA44, MLDSA65, MLDSA87\n");
    fprintf(fp, "default_algorithm=");
    if (config->default_sig_algorithm == PQ_SIG_MLDSA44) {
        fprintf(fp, "MLDSA44\n");
    } else if (config->default_sig_algorithm == PQ_SIG_MLDSA65) {
        fprintf(fp, "MLDSA65\n");
    } else if (config->default_sig_algorithm == PQ_SIG_MLDSA87) {
        fprintf(fp, "MLDSA87\n");
    }
    fprintf(fp, "# Allow classical signature fallback (Ed25519, ECDSA, RSA)\n");
    fprintf(fp, "enable_classical=%s\n\n", bool_to_string(config->enable_classical_sig));
    
    /* TLS section */
    fprintf(fp, "[tls]\n");
    fprintf(fp, "# Minimum TLS version: 1.2 or 1.3\n");
    fprintf(fp, "min_version=%s\n", 
            config->tls_min_version == TLS_VERSION_1_2 ? "1.2" : "1.3");
    fprintf(fp, "# Maximum TLS version: 1.2 or 1.3\n");
    fprintf(fp, "max_version=%s\n", 
            config->tls_max_version == TLS_VERSION_1_2 ? "1.2" : "1.3");
    fprintf(fp, "# Post-quantum only mode (disable all classical algorithms)\n");
    fprintf(fp, "pq_only_mode=%s\n\n", bool_to_string(config->enable_pq_only_mode));
    
    /* HPKE section */
    fprintf(fp, "[hpke]\n");
    fprintf(fp, "# Default HPKE KEM: X25519, MLKEM768, X25519_MLKEM768_CONCAT\n");
    fprintf(fp, "default_kem=");
    if (config->default_hpke_kem == HPKE_KEM_X25519) {
        fprintf(fp, "X25519\n");
    } else if (config->default_hpke_kem == HPKE_KEM_MLKEM768) {
        fprintf(fp, "MLKEM768\n");
    } else if (config->default_hpke_kem == HPKE_KEM_X25519_MLKEM768_CONCAT) {
        fprintf(fp, "X25519_MLKEM768_CONCAT\n");
    }
    fprintf(fp, "# Default HPKE AEAD: AES256GCM, CHACHA20POLY1305\n");
    fprintf(fp, "default_aead=");
    if (config->default_hpke_aead == HPKE_AEAD_AES256GCM) {
        fprintf(fp, "AES256GCM\n");
    } else if (config->default_hpke_aead == HPKE_AEAD_CHACHAPOLY) {
        fprintf(fp, "CHACHA20POLY1305\n");
    }
    fprintf(fp, "\n");
    
    /* Hybrid KEX section */
    fprintf(fp, "[hybrid_kex]\n");
    fprintf(fp, "# Hybrid mode: CONCAT or XOR\n");
    fprintf(fp, "default_mode=%s\n", 
            config->default_hybrid_mode == HYBRID_MODE_CONCAT ? "CONCAT" : "XOR");
    fprintf(fp, "# Classical KEX: X25519 or P256\n");
    fprintf(fp, "default_classical=%s\n\n", 
            config->default_classical_kex == HYBRID_CLASSICAL_X25519 ? "X25519" : "P256");
    
    /* Performance section */
    fprintf(fp, "[performance]\n");
    fprintf(fp, "# Force constant-time operations (recommended for security)\n");
    fprintf(fp, "constant_time=%s\n", bool_to_string(config->enable_constant_time));
    fprintf(fp, "# Use mlock for sensitive data (requires privileges)\n");
    fprintf(fp, "memory_lock=%s\n\n", bool_to_string(config->enable_memory_lock));
    
    /* Logging section */
    fprintf(fp, "[logging]\n");
    fprintf(fp, "# Log level: none, error, warn, info, debug\n");
    fprintf(fp, "log_level=");
    switch (config->log_level) {
        case 0: fprintf(fp, "none\n"); break;
        case 1: fprintf(fp, "error\n"); break;
        case 2: fprintf(fp, "warn\n"); break;
        case 3: fprintf(fp, "info\n"); break;
        case 4: fprintf(fp, "debug\n"); break;
        default: fprintf(fp, "warn\n"); break;
    }
    fprintf(fp, "# Enable performance benchmarking\n");
    fprintf(fp, "enable_benchmarking=%s\n", bool_to_string(config->enable_benchmarking));
    
    fclose(fp);
    return PQ_SUCCESS;
}

const char* pq_config_to_string(const pq_config_t *config) {
    static char buffer[2048];
    
    if (!config) {
        return NULL;
    }
    
    char *p = buffer;
    size_t remaining = sizeof(buffer);
    int written;

/* Helper macro to safely advance the buffer pointer */
#define SAFE_ADVANCE() do { \
    if (written < 0 || (size_t)written >= remaining) { \
        buffer[sizeof(buffer) - 1] = '\0'; \
        return buffer; \
    } \
    p += written; remaining -= (size_t)written; \
} while(0)

    /* Header */
    written = snprintf(p, remaining, "Post-Quantum TLS Configuration:\n");
    SAFE_ADVANCE();
    
    /* KEM configuration */
    written = snprintf(p, remaining, "\nKEM Configuration:\n");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Default Algorithm: ");
    SAFE_ADVANCE();

    if (config->default_kem_algorithm == PQ_KEM_MLKEM512) {
        written = snprintf(p, remaining, "ML-KEM-512\n");
    } else if (config->default_kem_algorithm == PQ_KEM_MLKEM768) {
        written = snprintf(p, remaining, "ML-KEM-768\n");
    } else if (config->default_kem_algorithm == PQ_KEM_MLKEM1024) {
        written = snprintf(p, remaining, "ML-KEM-1024\n");
    } else {
        written = snprintf(p, remaining, "Unknown\n");
    }
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Classical Fallback: %s\n",
                      config->enable_classical_kem ? "Enabled" : "Disabled");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Hybrid Mode: %s\n",
                      config->enable_hybrid_kem ? "Enabled" : "Disabled");
    SAFE_ADVANCE();

    /* Signature configuration */
    written = snprintf(p, remaining, "\nSignature Configuration:\n");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Default Algorithm: ");
    SAFE_ADVANCE();

    if (config->default_sig_algorithm == PQ_SIG_MLDSA44) {
        written = snprintf(p, remaining, "ML-DSA-44\n");
    } else if (config->default_sig_algorithm == PQ_SIG_MLDSA65) {
        written = snprintf(p, remaining, "ML-DSA-65\n");
    } else if (config->default_sig_algorithm == PQ_SIG_MLDSA87) {
        written = snprintf(p, remaining, "ML-DSA-87\n");
    } else {
        written = snprintf(p, remaining, "Unknown\n");
    }
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Classical Fallback: %s\n",
                      config->enable_classical_sig ? "Enabled" : "Disabled");
    SAFE_ADVANCE();

    /* TLS configuration */
    written = snprintf(p, remaining, "\nTLS Configuration:\n");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Version Range: TLS %s - %s\n",
                      config->tls_min_version == TLS_VERSION_1_2 ? "1.2" : "1.3",
                      config->tls_max_version == TLS_VERSION_1_2 ? "1.2" : "1.3");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  PQ-Only Mode: %s\n",
                      config->enable_pq_only_mode ? "Enabled" : "Disabled");
    SAFE_ADVANCE();

    /* HPKE configuration */
    written = snprintf(p, remaining, "\nHPKE Configuration:\n");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Default KEM: ");
    SAFE_ADVANCE();

    if (config->default_hpke_kem == HPKE_KEM_X25519) {
        written = snprintf(p, remaining, "X25519\n");
    } else if (config->default_hpke_kem == HPKE_KEM_MLKEM768) {
        written = snprintf(p, remaining, "ML-KEM-768\n");
    } else if (config->default_hpke_kem == HPKE_KEM_X25519_MLKEM768_CONCAT) {
        written = snprintf(p, remaining, "X25519+ML-KEM-768 (CONCAT)\n");
    } else {
        written = snprintf(p, remaining, "Unknown\n");
    }
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Default AEAD: ");
    SAFE_ADVANCE();

    if (config->default_hpke_aead == HPKE_AEAD_AES256GCM) {
        written = snprintf(p, remaining, "AES-256-GCM\n");
    } else if (config->default_hpke_aead == HPKE_AEAD_CHACHAPOLY) {
        written = snprintf(p, remaining, "ChaCha20-Poly1305\n");
    } else {
        written = snprintf(p, remaining, "Unknown\n");
    }
    SAFE_ADVANCE();

    /* Hybrid KEX configuration */
    written = snprintf(p, remaining, "\nHybrid KEX Configuration:\n");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Combination Mode: %s\n",
                      config->default_hybrid_mode == HYBRID_MODE_CONCAT ? "CONCAT" : "XOR");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Classical Algorithm: %s\n",
                      config->default_classical_kex == HYBRID_CLASSICAL_X25519 ? "X25519" : "P-256");
    SAFE_ADVANCE();

    /* Performance configuration */
    written = snprintf(p, remaining, "\nPerformance Configuration:\n");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Constant-Time Operations: %s\n",
                      config->enable_constant_time ? "Enabled" : "Disabled");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Memory Locking: %s\n",
                      config->enable_memory_lock ? "Enabled" : "Disabled");
    SAFE_ADVANCE();

    /* Logging configuration */
    written = snprintf(p, remaining, "\nLogging Configuration:\n");
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Log Level: ");
    SAFE_ADVANCE();

    switch (config->log_level) {
        case 0: written = snprintf(p, remaining, "None\n"); break;
        case 1: written = snprintf(p, remaining, "Error\n"); break;
        case 2: written = snprintf(p, remaining, "Warning\n"); break;
        case 3: written = snprintf(p, remaining, "Info\n"); break;
        case 4: written = snprintf(p, remaining, "Debug\n"); break;
        default: written = snprintf(p, remaining, "Unknown\n"); break;
    }
    SAFE_ADVANCE();

    written = snprintf(p, remaining, "  Benchmarking: %s\n",
                      config->enable_benchmarking ? "Enabled" : "Disabled");
    SAFE_ADVANCE();

#undef SAFE_ADVANCE
    return buffer;
}
