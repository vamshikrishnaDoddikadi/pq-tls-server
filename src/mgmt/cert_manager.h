/**
 * @file cert_manager.h
 * @brief X.509 certificate parsing, store management, self-signed generation
 */

#ifndef PQ_CERT_MANAGER_H
#define PQ_CERT_MANAGER_H

#include <stddef.h>

#define CERT_MAX_STORE 64

typedef struct {
    char filename[256];
    char subject[256];
    char issuer[256];
    char not_before[32];
    char not_after[32];
    char key_type[32];
    char sig_algo[64];
    char fingerprint[96];
    int  days_remaining;
    int  is_self_signed;
} cert_info_t;

/**
 * Parse X.509 certificate details from a PEM file.
 * @return 0 on success, -1 on error.
 */
int cert_parse_pem_file(const char *pem_path, cert_info_t *info);

/**
 * Parse X.509 certificate details from PEM data in memory.
 * @return 0 on success, -1 on error.
 */
int cert_parse_pem_data(const char *pem_data, size_t pem_len, cert_info_t *info);

/**
 * List certificates in a directory.
 * @return Number of certificates found, -1 on error.
 */
int cert_list_store(const char *store_dir, cert_info_t *certs, int max_certs);

/**
 * Generate a self-signed certificate.
 * @param cn      Common Name
 * @param org     Organization (can be NULL)
 * @param country Country code (can be NULL, 2-letter)
 * @param key_type "rsa" or "ecdsa"
 * @param days    Validity in days
 * @param sans    Subject Alternative Names, comma-separated (can be NULL)
 * @param cert_out_path Path to write certificate PEM
 * @param key_out_path  Path to write private key PEM
 * @return 0 on success, -1 on error.
 */
int cert_generate_self_signed(const char *cn, const char *org,
                              const char *country, const char *key_type,
                              int days, const char *sans,
                              const char *cert_out_path,
                              const char *key_out_path);

/**
 * Copy cert+key to target paths and trigger TLS reload.
 * @return 0 on success, -1 on error.
 */
int cert_apply(const char *cert_src, const char *key_src,
               const char *cert_dst, const char *key_dst);

/**
 * Save uploaded PEM data to the cert store directory.
 * @return 0 on success, -1 on error.
 */
int cert_save_upload(const char *store_dir, const char *name,
                     const char *cert_pem, size_t cert_len,
                     const char *key_pem, size_t key_len);

#endif /* PQ_CERT_MANAGER_H */
