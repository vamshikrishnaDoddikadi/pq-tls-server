/**
 * @file cert_manager.c
 * @brief X.509 certificate operations using OpenSSL APIs
 */

#include "cert_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static void x509_name_to_str(X509_NAME *name, char *buf, size_t buf_size) {
    if (!name || !buf || buf_size == 0) return;
    X509_NAME_oneline(name, buf, (int)buf_size);
}

static int asn1_time_days_remaining(const ASN1_TIME *t) {
    int day = 0, sec = 0;
    if (ASN1_TIME_diff(&day, &sec, NULL, t))
        return day;
    return -1;
}

static void asn1_time_to_str(const ASN1_TIME *t, char *buf, size_t buf_size) {
    if (!t || !buf || buf_size == 0) return;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) { buf[0] = '\0'; return; }
    ASN1_TIME_print(bio, t);
    int n = BIO_read(bio, buf, (int)(buf_size - 1));
    if (n < 0) n = 0;
    buf[n] = '\0';
    BIO_free(bio);
}

static void get_key_type(EVP_PKEY *pkey, char *buf, size_t buf_size) {
    if (!pkey || !buf || buf_size == 0) return;
    int id = EVP_PKEY_id(pkey);
    switch (id) {
    case EVP_PKEY_RSA:   snprintf(buf, buf_size, "RSA-%d", EVP_PKEY_bits(pkey)); break;
    case EVP_PKEY_EC:    snprintf(buf, buf_size, "ECDSA-%d", EVP_PKEY_bits(pkey)); break;
    case EVP_PKEY_ED25519: snprintf(buf, buf_size, "Ed25519"); break;
    case EVP_PKEY_ED448:   snprintf(buf, buf_size, "Ed448"); break;
    default:             snprintf(buf, buf_size, "Unknown(%d)", id); break;
    }
}

static void compute_fingerprint(X509 *cert, char *buf, size_t buf_size) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &len)) {
        size_t pos = 0;
        for (unsigned int i = 0; i < len && pos + 3 < buf_size; i++) {
            if (i > 0) buf[pos++] = ':';
            snprintf(buf + pos, buf_size - pos, "%02X", md[i]);
            pos += 2;
        }
        buf[pos] = '\0';
    } else {
        buf[0] = '\0';
    }
}

static int parse_x509(X509 *cert, cert_info_t *info) {
    if (!cert || !info) return -1;

    x509_name_to_str(X509_get_subject_name(cert), info->subject, sizeof(info->subject));
    x509_name_to_str(X509_get_issuer_name(cert), info->issuer, sizeof(info->issuer));

    asn1_time_to_str(X509_get0_notBefore(cert), info->not_before, sizeof(info->not_before));
    asn1_time_to_str(X509_get0_notAfter(cert), info->not_after, sizeof(info->not_after));

    info->days_remaining = asn1_time_days_remaining(X509_get0_notAfter(cert));

    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    get_key_type(pkey, info->key_type, sizeof(info->key_type));

    int nid = X509_get_signature_nid(cert);
    const char *sig_name = OBJ_nid2ln(nid);
    snprintf(info->sig_algo, sizeof(info->sig_algo), "%s", sig_name ? sig_name : "unknown");

    compute_fingerprint(cert, info->fingerprint, sizeof(info->fingerprint));

    info->is_self_signed = (X509_check_issued(cert, cert) == X509_V_OK) ? 1 : 0;

    return 0;
}

int cert_parse_pem_file(const char *pem_path, cert_info_t *info) {
    if (!pem_path || !info) return -1;
    memset(info, 0, sizeof(*info));

    FILE *fp = fopen(pem_path, "r");
    if (!fp) return -1;

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) return -1;

    /* Extract filename */
    const char *slash = strrchr(pem_path, '/');
    snprintf(info->filename, sizeof(info->filename), "%s", slash ? slash + 1 : pem_path);

    int ret = parse_x509(cert, info);
    X509_free(cert);
    return ret;
}

int cert_parse_pem_data(const char *pem_data, size_t pem_len, cert_info_t *info) {
    if (!pem_data || !info || pem_len == 0) return -1;
    memset(info, 0, sizeof(*info));

    BIO *bio = BIO_new_mem_buf(pem_data, (int)pem_len);
    if (!bio) return -1;

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) return -1;

    int ret = parse_x509(cert, info);
    X509_free(cert);
    return ret;
}

int cert_list_store(const char *store_dir, cert_info_t *certs, int max_certs) {
    if (!store_dir || !certs || max_certs <= 0) return -1;

    DIR *dir = opendir(store_dir);
    if (!dir) return -1;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && count < max_certs) {
        size_t name_len = strlen(ent->d_name);
        if (name_len < 4) continue;

        /* Only process .pem and .crt files */
        const char *ext = ent->d_name + name_len - 4;
        if (strcmp(ext, ".pem") != 0 && strcmp(ext, ".crt") != 0) continue;

        char path[2048];
        snprintf(path, sizeof(path), "%s/%s", store_dir, ent->d_name);

        if (cert_parse_pem_file(path, &certs[count]) == 0) {
            count++;
        }
    }

    closedir(dir);
    return count;
}

int cert_generate_self_signed(const char *cn, const char *org,
                              const char *country, const char *key_type,
                              int days, const char *sans,
                              const char *cert_out_path,
                              const char *key_out_path) {
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    int ret = -1;

    /* Generate key pair */
    EVP_PKEY_CTX *pctx = NULL;
    if (!key_type || strcmp(key_type, "rsa") == 0) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!pctx) goto cleanup;
        if (EVP_PKEY_keygen_init(pctx) <= 0) goto cleanup;
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) goto cleanup;
    } else if (strcmp(key_type, "ecdsa") == 0) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!pctx) goto cleanup;
        if (EVP_PKEY_keygen_init(pctx) <= 0) goto cleanup;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) goto cleanup;
    } else {
        goto cleanup;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto cleanup;

    /* Create X509 certificate */
    x509 = X509_new();
    if (!x509) goto cleanup;

    /* Random serial number per RFC 5280 */
    {
        unsigned char serial_bytes[16];
        RAND_bytes(serial_bytes, sizeof(serial_bytes));
        serial_bytes[0] &= 0x7F; /* Ensure positive */
        BIGNUM *bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
        if (bn) {
            BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x509));
            BN_free(bn);
        }
    }
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), (long)(days > 0 ? days : 365) * 86400L);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    if (cn) X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                        (unsigned char *)cn, -1, -1, 0);
    if (org) X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                         (unsigned char *)org, -1, -1, 0);
    if (country && strlen(country) == 2)
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                    (unsigned char *)country, -1, -1, 0);
    X509_set_issuer_name(x509, name);

    /* Add SANs if provided */
    if (sans && sans[0]) {
        char san_buf[1024];
        snprintf(san_buf, sizeof(san_buf), "%s", sans);

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);

        /* Build SAN string: "DNS:name1,DNS:name2,IP:1.2.3.4" */
        char san_ext[2048] = {0};
        char *saveptr = NULL;
        char *tok = strtok_r(san_buf, ",", &saveptr);
        while (tok) {
            while (*tok == ' ') tok++;
            if (san_ext[0]) strncat(san_ext, ",", sizeof(san_ext) - strlen(san_ext) - 1);

            /* Check if IP address */
            int is_ip = 1;
            for (const char *c = tok; *c; c++) {
                if (*c != '.' && (*c < '0' || *c > '9') && *c != ':') {
                    is_ip = 0;
                    break;
                }
            }

            char entry[256];
            snprintf(entry, sizeof(entry), "%s:%s", is_ip ? "IP" : "DNS", tok);
            strncat(san_ext, entry, sizeof(san_ext) - strlen(san_ext) - 1);

            tok = strtok_r(NULL, ",", &saveptr);
        }

        if (san_ext[0]) {
            X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx,
                                                       NID_subject_alt_name, san_ext);
            if (ext) {
                X509_add_ext(x509, ext, -1);
                X509_EXTENSION_free(ext);
            }
        }
    }

    /* Self-sign */
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) goto cleanup;

    /* Write cert */
    {
        FILE *fp = fopen(cert_out_path, "w");
        if (!fp) goto cleanup;
        PEM_write_X509(fp, x509);
        fclose(fp);
    }

    /* Write key */
    {
        FILE *fp = fopen(key_out_path, "w");
        if (!fp) { unlink(cert_out_path); goto cleanup; }
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(fp);
        chmod(key_out_path, 0600);
    }

    ret = 0;

cleanup:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    return ret;
}

int cert_apply(const char *cert_src, const char *key_src,
               const char *cert_dst, const char *key_dst) {
    if (!cert_src || !key_src || !cert_dst || !key_dst) return -1;

    /* Copy cert to temp, then rename for safer operation */
    FILE *src = fopen(cert_src, "r");
    if (!src) return -1;

    char tmp_cert[2048], tmp_key[2048];
    snprintf(tmp_cert, sizeof(tmp_cert), "%s.tmp", cert_dst);
    snprintf(tmp_key, sizeof(tmp_key), "%s.tmp", key_dst);

    FILE *dst = fopen(tmp_cert, "w");
    if (!dst) { fclose(src); return -1; }

    char buf[4096];
    size_t n;
    int err = 0;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) { err = 1; break; }
    }
    fclose(src);
    err = err || ferror(dst);
    fclose(dst);
    if (err) { unlink(tmp_cert); return -1; }

    /* Copy key */
    src = fopen(key_src, "r");
    if (!src) { unlink(tmp_cert); return -1; }
    dst = fopen(tmp_key, "w");
    if (!dst) { fclose(src); unlink(tmp_cert); return -1; }

    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) { err = 1; break; }
    }
    fclose(src);
    err = err || ferror(dst);
    fclose(dst);
    if (err) { unlink(tmp_cert); unlink(tmp_key); return -1; }

    /* Rename both — cert first, then key */
    if (rename(tmp_cert, cert_dst) != 0) {
        unlink(tmp_cert); unlink(tmp_key);
        return -1;
    }
    if (rename(tmp_key, key_dst) != 0) {
        unlink(tmp_key);
        return -1;
    }
    chmod(key_dst, 0600);

    return 0;
}

int cert_save_upload(const char *store_dir, const char *name,
                     const char *cert_pem, size_t cert_len,
                     const char *key_pem, size_t key_len) {
    if (!store_dir || !name || !cert_pem || cert_len == 0) return -1;

    /* Ensure store directory exists */
    mkdir(store_dir, 0700);

    char cert_path[2048], key_path[2048];
    snprintf(cert_path, sizeof(cert_path), "%s/%s.pem", store_dir, name);

    FILE *fp = fopen(cert_path, "w");
    if (!fp) return -1;
    fwrite(cert_pem, 1, cert_len, fp);
    fclose(fp);

    if (key_pem && key_len > 0) {
        snprintf(key_path, sizeof(key_path), "%s/%s-key.pem", store_dir, name);
        fp = fopen(key_path, "w");
        if (!fp) return -1;
        fwrite(key_pem, 1, key_len, fp);
        fclose(fp);
        chmod(key_path, 0600);
    }

    return 0;
}
