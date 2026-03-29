/**
 * @file config_writer.h
 * @brief INI config serializer with atomic write (tmp + rename)
 */

#ifndef PQ_CONFIG_WRITER_H
#define PQ_CONFIG_WRITER_H

#include "../core/server_config.h"

/**
 * Write the full server config to an INI file using atomic rename.
 * Writes to a temp file first, then renames over the target.
 *
 * @return 0 on success, -1 on error.
 */
int pq_server_config_save(const pq_server_config_t *cfg, const char *path);

/**
 * Track which settings have changed and whether a restart is needed.
 */
typedef struct {
    int restart_required;
    int runtime_applied;
    char changed_section[64];
} config_change_result_t;

/**
 * Check if a particular config section change requires a restart.
 * @return 1 if restart required, 0 if runtime-reloadable.
 */
int config_change_needs_restart(const char *section);

#endif /* PQ_CONFIG_WRITER_H */
