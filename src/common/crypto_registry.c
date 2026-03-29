/**
 * @file crypto_registry.c
 * @brief Crypto-Agility Algorithm Registry — Implementation
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 */

#include "crypto_registry.h"
#include "pq_errors.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <dirent.h>
#endif

/* ========================================================================
 * Internal Structures
 * ======================================================================== */

#define NEGOTIATION_LOG_SIZE 1024   /* ring buffer capacity */

typedef struct {
    void *handle;               /* dlopen handle */
    const char *path;           /* file path (strdup'd) */
    const pq_plugin_descriptor_t *desc;
} pq_loaded_plugin_t;

struct pq_registry {
    /* --- KEM providers --- */
    const pq_kem_provider_t *kems[PQ_REGISTRY_MAX_KEM_PROVIDERS];
    size_t kem_count;

    /* --- SIG providers --- */
    const pq_sig_provider_t *sigs[PQ_REGISTRY_MAX_SIG_PROVIDERS];
    size_t sig_count;

    /* --- Combiners --- */
    const pq_hybrid_combiner_t *combiners[PQ_REGISTRY_MAX_COMBINERS];
    size_t combiner_count;

    /* --- Hybrid KEM pairs --- */
    pq_hybrid_kem_t hybrids[PQ_REGISTRY_MAX_HYBRID_KEMS];
    size_t hybrid_count;

    /* --- Preference ordering (indices into hybrids / kems / sigs) --- */
    const char *kem_preference[PQ_REGISTRY_MAX_HYBRID_KEMS];
    size_t kem_pref_count;

    const char *sig_preference[PQ_REGISTRY_MAX_SIG_PROVIDERS];
    size_t sig_pref_count;

    /* --- Policy --- */
    pq_crypto_policy_t policy;

    /* --- Negotiation audit log (ring buffer) --- */
    pq_negotiation_log_entry_t neg_log[NEGOTIATION_LOG_SIZE];
    size_t neg_log_head;
    size_t neg_log_count;
    pthread_mutex_t neg_log_mutex;

    /* --- Loaded plugins --- */
    pq_loaded_plugin_t plugins[PQ_REGISTRY_MAX_PLUGINS];
    size_t plugin_count;
};

/* ========================================================================
 * Helpers
 * ======================================================================== */

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

pq_registry_t *pq_registry_create(void)
{
    pq_registry_t *reg = calloc(1, sizeof(*reg));
    if (!reg) return NULL;

    pthread_mutex_init(&reg->neg_log_mutex, NULL);

    /* Sensible default policy */
    reg->policy.allow_classical_only = true;
    reg->policy.min_nist_level       = 1;
    reg->policy.log_negotiation      = true;
    reg->policy.prefer_hybrid        = true;

    return reg;
}

void pq_registry_destroy(pq_registry_t *reg)
{
    if (!reg) return;

    /* Cleanup providers */
    for (size_t i = 0; i < reg->kem_count; i++) {
        if (reg->kems[i] && reg->kems[i]->cleanup)
            reg->kems[i]->cleanup();
    }
    for (size_t i = 0; i < reg->sig_count; i++) {
        if (reg->sigs[i] && reg->sigs[i]->cleanup)
            reg->sigs[i]->cleanup();
    }

    /* Unload plugins */
#ifndef _WIN32
    for (size_t i = 0; i < reg->plugin_count; i++) {
        if (reg->plugins[i].handle)
            dlclose(reg->plugins[i].handle);
        free((void *)reg->plugins[i].path);
    }
#endif

    pthread_mutex_destroy(&reg->neg_log_mutex);
    free(reg);
}

/* ========================================================================
 * Provider Registration
 * ======================================================================== */

int pq_registry_register_kem(pq_registry_t *reg, const pq_kem_provider_t *provider)
{
    if (!reg || !provider || !provider->name)
        return PQ_ERR_INVALID_PARAMETER;
    if (reg->kem_count >= PQ_REGISTRY_MAX_KEM_PROVIDERS)
        return PQ_ERR_BUFFER_TOO_SMALL;

    /* Check for duplicates */
    const char *pname = provider->name();
    for (size_t i = 0; i < reg->kem_count; i++) {
        if (strcmp(reg->kems[i]->name(), pname) == 0)
            return PQ_ERR_INVALID_PARAMETER; /* duplicate */
    }

    reg->kems[reg->kem_count++] = provider;
    return PQ_SUCCESS;
}

int pq_registry_register_sig(pq_registry_t *reg, const pq_sig_provider_t *provider)
{
    if (!reg || !provider || !provider->name)
        return PQ_ERR_INVALID_PARAMETER;
    if (reg->sig_count >= PQ_REGISTRY_MAX_SIG_PROVIDERS)
        return PQ_ERR_BUFFER_TOO_SMALL;

    const char *pname = provider->name();
    for (size_t i = 0; i < reg->sig_count; i++) {
        if (strcmp(reg->sigs[i]->name(), pname) == 0)
            return PQ_ERR_INVALID_PARAMETER;
    }

    reg->sigs[reg->sig_count++] = provider;
    return PQ_SUCCESS;
}

int pq_registry_register_combiner(pq_registry_t *reg, const pq_hybrid_combiner_t *combiner)
{
    if (!reg || !combiner)
        return PQ_ERR_INVALID_PARAMETER;
    if (reg->combiner_count >= PQ_REGISTRY_MAX_COMBINERS)
        return PQ_ERR_BUFFER_TOO_SMALL;

    reg->combiners[reg->combiner_count++] = combiner;
    return PQ_SUCCESS;
}

int pq_registry_register_hybrid(pq_registry_t *reg, const pq_hybrid_kem_t *hybrid)
{
    if (!reg || !hybrid || !hybrid->tls_group)
        return PQ_ERR_INVALID_PARAMETER;
    if (reg->hybrid_count >= PQ_REGISTRY_MAX_HYBRID_KEMS)
        return PQ_ERR_BUFFER_TOO_SMALL;

    reg->hybrids[reg->hybrid_count++] = *hybrid;
    return PQ_SUCCESS;
}

/* ========================================================================
 * Dynamic Plugin Loading
 * ======================================================================== */

int pq_registry_load_plugin(pq_registry_t *reg, const char *path)
{
#ifdef _WIN32
    (void)reg; (void)path;
    return PQ_ERR_UNSUPPORTED_ALGORITHM; /* not yet implemented on Windows */
#else
    if (!reg || !path)
        return PQ_ERR_INVALID_PARAMETER;
    if (reg->plugin_count >= PQ_REGISTRY_MAX_PLUGINS)
        return PQ_ERR_BUFFER_TOO_SMALL;

    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "[registry] dlopen(%s): %s\n", path, dlerror());
        return PQ_ERR_ALGORITHM_NOT_AVAILABLE;
    }

    pq_plugin_init_fn init_fn = (pq_plugin_init_fn)dlsym(handle, "pq_plugin_init");
    if (!init_fn) {
        fprintf(stderr, "[registry] %s: missing pq_plugin_init symbol\n", path);
        dlclose(handle);
        return PQ_ERR_ALGORITHM_NOT_AVAILABLE;
    }

    const pq_plugin_descriptor_t *desc = init_fn();
    if (!desc || desc->api_version != PQ_PLUGIN_API_VERSION) {
        fprintf(stderr, "[registry] %s: API version mismatch (got %d, want %d)\n",
                path, desc ? desc->api_version : -1, PQ_PLUGIN_API_VERSION);
        dlclose(handle);
        return PQ_ERR_INVALID_PARAMETER;
    }

    /* Register all providers from this plugin */
    int rc;
    for (size_t i = 0; i < desc->kem_count; i++) {
        rc = pq_registry_register_kem(reg, desc->kem_providers[i]);
        if (rc != PQ_SUCCESS)
            fprintf(stderr, "[registry] %s: failed to register KEM %zu: %s\n",
                    path, i, pq_error_string(rc));
    }
    for (size_t i = 0; i < desc->sig_count; i++) {
        rc = pq_registry_register_sig(reg, desc->sig_providers[i]);
        if (rc != PQ_SUCCESS)
            fprintf(stderr, "[registry] %s: failed to register SIG %zu: %s\n",
                    path, i, pq_error_string(rc));
    }

    /* Track plugin for cleanup */
    pq_loaded_plugin_t *p = &reg->plugins[reg->plugin_count++];
    p->handle = handle;
    p->path   = strdup(path);
    p->desc   = desc;

    fprintf(stderr, "[registry] loaded plugin: %s v%s (%zu KEMs, %zu SIGs)\n",
            desc->plugin_name, desc->plugin_version,
            desc->kem_count, desc->sig_count);

    return PQ_SUCCESS;
#endif
}

int pq_registry_load_plugins(pq_registry_t *reg, const char *dir)
{
#ifdef _WIN32
    (void)reg; (void)dir;
    return 0;
#else
    if (!reg || !dir) return PQ_ERR_INVALID_PARAMETER;

    DIR *d = opendir(dir);
    if (!d) return 0; /* no plugin directory is not an error */

    int loaded = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len < 4 || strcmp(ent->d_name + len - 3, ".so") != 0)
            continue;

        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (pq_registry_load_plugin(reg, path) == PQ_SUCCESS)
            loaded++;
    }
    closedir(d);
    return loaded;
#endif
}

/* ========================================================================
 * Provider Lookup
 * ======================================================================== */

const pq_kem_provider_t *pq_registry_find_kem(const pq_registry_t *reg,
                                                const char *name)
{
    if (!reg || !name) return NULL;
    for (size_t i = 0; i < reg->kem_count; i++) {
        if (strcmp(reg->kems[i]->name(), name) == 0)
            return reg->kems[i];
    }
    return NULL;
}

const pq_sig_provider_t *pq_registry_find_sig(const pq_registry_t *reg,
                                                const char *name)
{
    if (!reg || !name) return NULL;
    for (size_t i = 0; i < reg->sig_count; i++) {
        if (strcmp(reg->sigs[i]->name(), name) == 0)
            return reg->sigs[i];
    }
    return NULL;
}

const pq_hybrid_combiner_t *pq_registry_find_combiner(const pq_registry_t *reg,
                                                       pq_combiner_method_t method)
{
    if (!reg) return NULL;
    for (size_t i = 0; i < reg->combiner_count; i++) {
        if (reg->combiners[i]->method == method)
            return reg->combiners[i];
    }
    return NULL;
}

const pq_hybrid_kem_t *pq_registry_find_hybrid(const pq_registry_t *reg,
                                                 const char *tls_group)
{
    if (!reg || !tls_group) return NULL;
    for (size_t i = 0; i < reg->hybrid_count; i++) {
        if (reg->hybrids[i].tls_group &&
            strcmp(reg->hybrids[i].tls_group, tls_group) == 0)
            return &reg->hybrids[i];
    }
    return NULL;
}

/* ========================================================================
 * Enumeration
 * ======================================================================== */

size_t pq_registry_list_kems(const pq_registry_t *reg,
                              const pq_kem_provider_t **out, size_t max)
{
    if (!reg || !out) return 0;
    size_t n = reg->kem_count < max ? reg->kem_count : max;
    for (size_t i = 0; i < n; i++)
        out[i] = reg->kems[i];
    return n;
}

size_t pq_registry_list_sigs(const pq_registry_t *reg,
                              const pq_sig_provider_t **out, size_t max)
{
    if (!reg || !out) return 0;
    size_t n = reg->sig_count < max ? reg->sig_count : max;
    for (size_t i = 0; i < n; i++)
        out[i] = reg->sigs[i];
    return n;
}

size_t pq_registry_list_hybrids(const pq_registry_t *reg,
                                 const pq_hybrid_kem_t **out, size_t max)
{
    if (!reg || !out) return 0;
    size_t n = reg->hybrid_count < max ? reg->hybrid_count : max;
    for (size_t i = 0; i < n; i++)
        out[i] = &reg->hybrids[i];
    return n;
}

size_t pq_registry_filter_kems_by_level(const pq_registry_t *reg,
                                         int min_level,
                                         const pq_kem_provider_t **out,
                                         size_t max)
{
    if (!reg || !out) return 0;
    size_t n = 0;
    for (size_t i = 0; i < reg->kem_count && n < max; i++) {
        const pq_algorithm_metadata_t *m = reg->kems[i]->metadata();
        if (m && m->nist_level >= min_level)
            out[n++] = reg->kems[i];
    }
    return n;
}

size_t pq_registry_filter_kems_by_family(const pq_registry_t *reg,
                                          pq_algorithm_family_t family,
                                          const pq_kem_provider_t **out,
                                          size_t max)
{
    if (!reg || !out) return 0;
    size_t n = 0;
    for (size_t i = 0; i < reg->kem_count && n < max; i++) {
        const pq_algorithm_metadata_t *m = reg->kems[i]->metadata();
        if (m && m->family == family)
            out[n++] = reg->kems[i];
    }
    return n;
}

/* ========================================================================
 * Preference Ordering & TLS Group Generation
 * ======================================================================== */

int pq_registry_set_kem_preference(pq_registry_t *reg, const char **names)
{
    if (!reg || !names) return PQ_ERR_INVALID_PARAMETER;

    reg->kem_pref_count = 0;
    for (size_t i = 0; names[i] != NULL; i++) {
        if (reg->kem_pref_count >= PQ_REGISTRY_MAX_HYBRID_KEMS)
            break;
        /* Validate: must be a known hybrid or KEM name */
        if (!pq_registry_find_hybrid(reg, names[i]) &&
            !pq_registry_find_kem(reg, names[i])) {
            fprintf(stderr, "[registry] unknown KEM preference: %s\n", names[i]);
            return PQ_ERR_INVALID_PARAMETER;
        }
        reg->kem_preference[reg->kem_pref_count++] = names[i];
    }
    return PQ_SUCCESS;
}

int pq_registry_set_sig_preference(pq_registry_t *reg, const char **names)
{
    if (!reg || !names) return PQ_ERR_INVALID_PARAMETER;

    reg->sig_pref_count = 0;
    for (size_t i = 0; names[i] != NULL; i++) {
        if (reg->sig_pref_count >= PQ_REGISTRY_MAX_SIG_PROVIDERS)
            break;
        if (!pq_registry_find_sig(reg, names[i])) {
            fprintf(stderr, "[registry] unknown SIG preference: %s\n", names[i]);
            return PQ_ERR_INVALID_PARAMETER;
        }
        reg->sig_preference[reg->sig_pref_count++] = names[i];
    }
    return PQ_SUCCESS;
}

/* Helper: check if group name is already present in a colon-separated buffer */
static int group_already_in_buf(const char *buf, const char *group)
{
    if (!buf[0]) return 0;
    const char *p = buf;
    size_t glen = strlen(group);
    while (p) {
        if (strncmp(p, group, glen) == 0 &&
            (p[glen] == ':' || p[glen] == '\0'))
            return 1;
        p = strchr(p, ':');
        if (p) p++;
    }
    return 0;
}

int pq_registry_generate_groups_string(const pq_registry_t *reg,
                                        char *buf, size_t buf_size)
{
    if (!reg || !buf || buf_size == 0)
        return PQ_ERR_INVALID_PARAMETER;

    buf[0] = '\0';
    size_t offset = 0;

    /* If preference list is set, use it */
    if (reg->kem_pref_count > 0) {
        for (size_t i = 0; i < reg->kem_pref_count; i++) {
            const char *name = reg->kem_preference[i];

            /* Look up the TLS group name */
            const char *group = name;
            const pq_hybrid_kem_t *h = pq_registry_find_hybrid(reg, name);
            if (h) group = h->tls_group;

            /* Skip NULL or empty group names */
            if (!group || !group[0]) continue;

            /* Dedup: skip if already in buffer */
            if (group_already_in_buf(buf, group)) continue;

            int written;
            if (offset > 0) {
                written = snprintf(buf + offset, buf_size - offset, ":%s", group);
            } else {
                written = snprintf(buf + offset, buf_size - offset, "%s", group);
            }
            if (written < 0 || (size_t)written >= buf_size - offset)
                return PQ_ERR_BUFFER_TOO_SMALL;
            offset += (size_t)written;
        }
    } else {
        /* Default: list all hybrids first, then classical KEMs */
        for (size_t i = 0; i < reg->hybrid_count; i++) {
            if (!reg->hybrids[i].tls_group || !reg->hybrids[i].tls_group[0])
                continue;

            /* Check min NIST level policy */
            if (reg->hybrids[i].nist_level < reg->policy.min_nist_level)
                continue;

            /* Dedup: skip if already in buffer */
            if (group_already_in_buf(buf, reg->hybrids[i].tls_group))
                continue;

            int written;
            if (offset > 0) {
                written = snprintf(buf + offset, buf_size - offset,
                                   ":%s", reg->hybrids[i].tls_group);
            } else {
                written = snprintf(buf + offset, buf_size - offset,
                                   "%s", reg->hybrids[i].tls_group);
            }
            if (written < 0 || (size_t)written >= buf_size - offset)
                return PQ_ERR_BUFFER_TOO_SMALL;
            offset += (size_t)written;
        }

        /* Classical fallback (if allowed by policy) */
        if (reg->policy.allow_classical_only) {
            for (size_t i = 0; i < reg->kem_count; i++) {
                const pq_algorithm_metadata_t *m = reg->kems[i]->metadata();
                if (!m || m->family != PQ_ALG_FAMILY_CLASSICAL) continue;
                if (!m->tls_group || !m->tls_group[0]) continue;

                /* Dedup: skip if already in buffer */
                if (group_already_in_buf(buf, m->tls_group)) continue;

                int written;
                if (offset > 0) {
                    written = snprintf(buf + offset, buf_size - offset,
                                       ":%s", m->tls_group);
                } else {
                    written = snprintf(buf + offset, buf_size - offset,
                                       "%s", m->tls_group);
                }
                if (written < 0 || (size_t)written >= buf_size - offset)
                    return PQ_ERR_BUFFER_TOO_SMALL;
                offset += (size_t)written;
            }
        }
    }

    return (int)offset;
}

/* ========================================================================
 * Policy
 * ======================================================================== */

int pq_registry_set_policy(pq_registry_t *reg, const pq_crypto_policy_t *policy)
{
    if (!reg || !policy) return PQ_ERR_INVALID_PARAMETER;
    reg->policy = *policy;
    return PQ_SUCCESS;
}

const pq_crypto_policy_t *pq_registry_get_policy(const pq_registry_t *reg)
{
    if (!reg) return NULL;
    return &reg->policy;
}

/* ========================================================================
 * Negotiation Audit Log
 * ======================================================================== */

int pq_registry_log_negotiation(pq_registry_t *reg,
                                 const pq_negotiation_log_entry_t *entry)
{
    if (!reg || !entry) return PQ_ERR_INVALID_PARAMETER;

    pthread_mutex_lock(&reg->neg_log_mutex);

    pq_negotiation_log_entry_t *slot = &reg->neg_log[reg->neg_log_head];
    *slot = *entry;
    if (slot->timestamp_us == 0)
        slot->timestamp_us = now_us();

    reg->neg_log_head = (reg->neg_log_head + 1) % NEGOTIATION_LOG_SIZE;
    if (reg->neg_log_count < NEGOTIATION_LOG_SIZE)
        reg->neg_log_count++;

    pthread_mutex_unlock(&reg->neg_log_mutex);
    return PQ_SUCCESS;
}

size_t pq_registry_get_negotiation_log(const pq_registry_t *reg,
                                        pq_negotiation_log_entry_t *out,
                                        size_t max)
{
    if (!reg || !out) return 0;

    /* Cast away const for mutex (readers still need the lock) */
    pq_registry_t *mutable_reg = (pq_registry_t *)reg;
    pthread_mutex_lock(&mutable_reg->neg_log_mutex);

    size_t n = reg->neg_log_count < max ? reg->neg_log_count : max;

    /* Read from oldest to newest */
    size_t start;
    if (reg->neg_log_count < NEGOTIATION_LOG_SIZE)
        start = 0;
    else
        start = reg->neg_log_head; /* oldest entry */

    for (size_t i = 0; i < n; i++) {
        size_t idx = (start + (reg->neg_log_count - n) + i) % NEGOTIATION_LOG_SIZE;
        out[i] = reg->neg_log[idx];
    }

    pthread_mutex_unlock(&mutable_reg->neg_log_mutex);
    return n;
}

/* ========================================================================
 * Capability Reporting (JSON)
 * ======================================================================== */

int pq_registry_to_json(const pq_registry_t *reg, char *buf, size_t buf_size)
{
    if (!reg || !buf || buf_size == 0) return PQ_ERR_INVALID_PARAMETER;

    size_t offset = 0;
    int w;

    w = snprintf(buf, buf_size, "{\"kem_providers\":[");
    if (w < 0) return PQ_ERR_BUFFER_TOO_SMALL;
    offset += (size_t)w;

    for (size_t i = 0; i < reg->kem_count; i++) {
        const pq_algorithm_metadata_t *m = reg->kems[i]->metadata();
        if (!m) continue;

        w = snprintf(buf + offset, buf_size - offset,
                     "%s{\"name\":\"%s\",\"family\":%d,\"status\":%d,"
                     "\"nist_level\":%d,\"pk_size\":%zu,\"sk_size\":%zu,"
                     "\"ct_size\":%zu,\"ss_size\":%zu,\"available\":%s}",
                     i > 0 ? "," : "",
                     m->name, m->family, m->status, m->nist_level,
                     m->pk_size, m->sk_size, m->ct_size, m->ss_size,
                     reg->kems[i]->is_available() ? "true" : "false");
        if (w < 0 || (size_t)w >= buf_size - offset)
            return PQ_ERR_BUFFER_TOO_SMALL;
        offset += (size_t)w;
    }

    w = snprintf(buf + offset, buf_size - offset, "],\"sig_providers\":[");
    if (w < 0 || (size_t)w >= buf_size - offset)
        return PQ_ERR_BUFFER_TOO_SMALL;
    offset += (size_t)w;

    for (size_t i = 0; i < reg->sig_count; i++) {
        const pq_algorithm_metadata_t *m = reg->sigs[i]->metadata();
        if (!m) continue;

        w = snprintf(buf + offset, buf_size - offset,
                     "%s{\"name\":\"%s\",\"family\":%d,\"status\":%d,"
                     "\"nist_level\":%d,\"pk_size\":%zu,\"sig_size\":%zu,"
                     "\"available\":%s}",
                     i > 0 ? "," : "",
                     m->name, m->family, m->status, m->nist_level,
                     m->pk_size, m->ct_size,
                     reg->sigs[i]->is_available() ? "true" : "false");
        if (w < 0 || (size_t)w >= buf_size - offset)
            return PQ_ERR_BUFFER_TOO_SMALL;
        offset += (size_t)w;
    }

    w = snprintf(buf + offset, buf_size - offset, "],\"hybrid_kems\":[");
    if (w < 0 || (size_t)w >= buf_size - offset)
        return PQ_ERR_BUFFER_TOO_SMALL;
    offset += (size_t)w;

    for (size_t i = 0; i < reg->hybrid_count; i++) {
        const pq_hybrid_kem_t *h = &reg->hybrids[i];
        w = snprintf(buf + offset, buf_size - offset,
                     "%s{\"label\":\"%s\",\"tls_group\":\"%s\","
                     "\"nist_level\":%d}",
                     i > 0 ? "," : "",
                     h->label ? h->label : "",
                     h->tls_group ? h->tls_group : "",
                     h->nist_level);
        if (w < 0 || (size_t)w >= buf_size - offset)
            return PQ_ERR_BUFFER_TOO_SMALL;
        offset += (size_t)w;
    }

    w = snprintf(buf + offset, buf_size - offset,
                 "],\"policy\":{\"allow_classical_only\":%s,"
                 "\"min_nist_level\":%d,\"log_negotiation\":%s,"
                 "\"prefer_hybrid\":%s}}",
                 reg->policy.allow_classical_only ? "true" : "false",
                 reg->policy.min_nist_level,
                 reg->policy.log_negotiation ? "true" : "false",
                 reg->policy.prefer_hybrid ? "true" : "false");
    if (w < 0 || (size_t)w >= buf_size - offset)
        return PQ_ERR_BUFFER_TOO_SMALL;
    offset += (size_t)w;

    return (int)offset;
}

size_t pq_registry_kem_count(const pq_registry_t *reg)
{
    return reg ? reg->kem_count : 0;
}

size_t pq_registry_sig_count(const pq_registry_t *reg)
{
    return reg ? reg->sig_count : 0;
}
