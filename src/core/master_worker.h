/*
 * master_worker.h - Master/Worker process architecture for PQ-TLS server
 *
 * Implements a fork-based multi-worker architecture with:
 * - Master process supervision and worker management
 * - Worker process lifecycle (startup, signal handling, graceful shutdown)
 * - Inter-process control via pipes for reload and shutdown signaling
 * - Crash detection and automatic restart with backoff
 */

#ifndef PQ_MASTER_WORKER_H
#define PQ_MASTER_WORKER_H

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Worker process state enumeration */
typedef enum {
    PQ_WORKER_RUNNING,        /* Worker is running normally */
    PQ_WORKER_STOPPING,       /* Worker is shutting down gracefully */
    PQ_WORKER_STOPPED,        /* Worker stopped normally */
    PQ_WORKER_CRASHED         /* Worker crashed unexpectedly */
} pq_worker_state_t;

/* Control message types sent from master to workers */
typedef enum {
    PQ_CTL_SHUTDOWN = 1,      /* Graceful shutdown */
    PQ_CTL_RELOAD = 2,        /* Reload TLS certificates */
    PQ_CTL_STATUS = 3         /* Request status report */
} pq_ctl_msg_t;

/* Per-worker metadata maintained by master */
typedef struct {
    pid_t              pid;                /* Worker process ID */
    pq_worker_state_t  state;              /* Current state */
    int                restart_count;      /* Number of restarts */
    time_t             started_at;         /* When worker was started */
    time_t             stopped_at;         /* When worker stopped */
    int                pipe_fd[2];         /* Control pipe: [0]=read, [1]=write */
    int                last_exit_status;   /* Last exit status or signal */
    int                graceful_timeout;   /* Timeout for graceful shutdown */
} pq_worker_info_t;

/* Master process structure */
typedef struct {
    int                 worker_count;      /* Number of workers to maintain */
    pq_worker_info_t   *workers;           /* Array of worker info structs */
    volatile sig_atomic_t running;         /* Master running flag */
    volatile sig_atomic_t sighup_pending;  /* SIGHUP received */
    volatile sig_atomic_t sigterm_pending; /* SIGTERM received */
    int                 listen_fd;         /* Shared listen socket FD */
    const void         *config;            /* Server config (pq_server_config_t*) */
    int                 max_restarts;      /* Max restarts per worker before giving up */
    int                 restart_delay;     /* Seconds to wait between restart attempts */
    int                 crash_timeout;     /* Seconds: if worker crashes within this window, escalate */
} pq_master_t;

/*
 * pq_master_create - Create a new master process structure
 *
 * @param config       - Pointer to pq_server_config_t configuration
 * @param listen_fd    - Listening socket file descriptor (will be shared with workers)
 * @param worker_count - Number of worker processes to spawn (0 = use CPU count)
 *
 * Returns: Allocated pq_master_t on success, NULL on failure
 */
pq_master_t* pq_master_create(const void *config, int listen_fd, int worker_count);

/*
 * pq_master_destroy - Free master process structure and resources
 *
 * Closes pipes and frees allocated memory. Does NOT kill workers.
 *
 * @param m - Master structure to destroy
 */
void pq_master_destroy(pq_master_t *m);

/*
 * pq_master_run - Main supervisor loop (blocks until shutdown)
 *
 * Sets up signal handlers, forks workers, and monitors them:
 * - Spawns initial worker processes
 * - Enters waitpid() loop to supervise workers
 * - Restarts crashed workers (subject to max_restarts and crash_timeout)
 * - Forwards SIGHUP to all workers for certificate reload
 * - On SIGTERM/SIGINT, initiates graceful shutdown
 *
 * @param m - Master structure
 *
 * Returns: 0 on clean shutdown, non-zero on error
 */
int pq_master_run(pq_master_t *m);

/*
 * pq_master_shutdown - Initiate graceful shutdown of all workers
 *
 * Sends PQ_CTL_SHUTDOWN to all workers via their control pipes.
 * Allows connections to drain before forcing termination.
 *
 * @param m - Master structure
 */
void pq_master_shutdown(pq_master_t *m);

/*
 * pq_master_reload - Request certificate reload from all workers
 *
 * Sends PQ_CTL_RELOAD control message to all running workers.
 * Workers should call pq_conn_manager_reload() upon receiving this.
 *
 * @param m - Master structure
 */
void pq_master_reload(pq_master_t *m);

/*
 * pq_master_worker_count - Get number of currently running workers
 *
 * @param m - Master structure
 *
 * Returns: Count of workers in PQ_WORKER_RUNNING state
 */
int pq_master_worker_count(const pq_master_t *m);

/*
 * pq_master_get_worker - Get info about a specific worker
 *
 * @param m      - Master structure
 * @param index  - Worker index (0 to worker_count-1)
 *
 * Returns: Pointer to worker info struct, or NULL if index out of bounds
 */
const pq_worker_info_t* pq_master_get_worker(const pq_master_t *m, int index);

/*
 * pq_worker_main - Worker process main entry point
 *
 * Must be called by forked worker process. Sets up signal handlers,
 * initializes control pipe monitoring, and runs the connection handler loop.
 *
 * @param config          - Pointer to pq_server_config_t
 * @param listen_fd       - Inherited listening socket
 * @param control_pipe_rd - Read end of control pipe (write end closed)
 *
 * Returns: 0 on graceful shutdown, non-zero on error
 * Does not return on crash/fatal signal
 */
int pq_worker_main(const void *config, int listen_fd, int control_pipe_rd);

#ifdef __cplusplus
}
#endif

#endif /* PQ_MASTER_WORKER_H */
