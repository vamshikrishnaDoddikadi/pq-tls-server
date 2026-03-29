/*
 * master_worker.c - Master/Worker process architecture implementation
 *
 * Implements fork-based multi-worker architecture with:
 * - Master process creation and worker supervision
 * - Worker lifecycle management
 * - Signal handling (SIGHUP for reload, SIGTERM/SIGINT for shutdown)
 * - Crash detection with automatic restart and backoff
 * - Inter-process communication via pipes
 */

#include "master_worker.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <syslog.h>

/* Forward declarations */
static int _pq_fork_worker(pq_master_t *m, int worker_idx);
static void _pq_master_signal_handler(int sig);
static void _pq_worker_signal_handler(int sig);
static int _pq_worker_read_control_message(int pipe_fd, pq_ctl_msg_t *msg);
static int _pq_worker_send_control_message(pq_master_t *m, int worker_idx, pq_ctl_msg_t msg);
static void _pq_master_reap_workers(pq_master_t *m, int block);
static int _pq_get_cpu_count(void);
static int _pq_set_nonblocking(int fd);

/* Global state for signal handlers */
static volatile sig_atomic_t g_master_running = 1;
static volatile sig_atomic_t g_master_sighup = 0;
static volatile sig_atomic_t g_master_sigterm = 0;
static volatile sig_atomic_t g_worker_running = 1;

/* Master signal handler */
static void _pq_master_signal_handler(int sig) {
    switch (sig) {
    case SIGHUP:
        g_master_sighup = 1;
        break;
    case SIGTERM:
    case SIGINT:
        g_master_sigterm = 1;
        g_master_running = 0;
        break;
    case SIGCHLD:
        /* Handled by waitpid() in main loop */
        break;
    default:
        break;
    }
}

/* Worker signal handler */
static void _pq_worker_signal_handler(int sig) {
    switch (sig) {
    case SIGTERM:
    case SIGINT:
        g_worker_running = 0;
        break;
    case SIGHUP:
        /* Will be handled via pipe, not signal */
        break;
    default:
        break;
    }
}

/*
 * _pq_get_cpu_count - Determine number of CPUs available
 *
 * Returns: Number of online processors, or 1 if detection fails
 */
static int _pq_get_cpu_count(void) {
#ifdef _SC_NPROCESSORS_ONLN
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count > 0) {
        return (int)count;
    }
#endif
    return 1;
}

/*
 * _pq_set_nonblocking - Set file descriptor to non-blocking mode
 *
 * @param fd - File descriptor
 *
 * Returns: 0 on success, -1 on error
 */
static int _pq_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
}

/*
 * _pq_worker_send_control_message - Send control message from master to worker
 *
 * @param m           - Master structure
 * @param worker_idx  - Worker index in workers array
 * @param msg         - Control message type
 *
 * Returns: 0 on success, -1 on failure
 */
static int _pq_worker_send_control_message(pq_master_t *m, int worker_idx, pq_ctl_msg_t msg) {
    if (worker_idx < 0 || worker_idx >= m->worker_count) {
        return -1;
    }

    pq_worker_info_t *w = &m->workers[worker_idx];
    if (w->pipe_fd[1] < 0 || w->state != PQ_WORKER_RUNNING) {
        return -1;
    }

    unsigned char msg_byte = (unsigned char)msg;
    ssize_t nwritten = write(w->pipe_fd[1], &msg_byte, 1);
    if (nwritten == 1) {
        return 0;
    }

    if (nwritten < 0 && errno == EPIPE) {
        /* Worker has closed its end, it's likely dead */
        return -1;
    }

    return -1;
}

/*
 * _pq_worker_read_control_message - Read control message from pipe
 *
 * Non-blocking read. Returns 0 if no message available.
 *
 * @param pipe_fd - Read end of control pipe
 * @param msg     - Output: message type
 *
 * Returns: 1 if message read, 0 if no data available, -1 on error
 */
static int _pq_worker_read_control_message(int pipe_fd, pq_ctl_msg_t *msg) {
    unsigned char msg_byte;
    ssize_t nread = read(pipe_fd, &msg_byte, 1);

    if (nread == 1) {
        *msg = (pq_ctl_msg_t)msg_byte;
        return 1;
    }

    if (nread == 0) {
        /* EOF: master has closed its end */
        return 0;
    }

    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* No data available */
        }
        return -1; /* Real error */
    }

    return 0;
}

/*
 * _pq_fork_worker - Fork a single worker process
 *
 * @param m            - Master structure
 * @param worker_idx   - Index in workers array
 *
 * Returns: 0 if child process, 1 if parent, -1 on error
 */
static int _pq_fork_worker(pq_master_t *m, int worker_idx) {
    pq_worker_info_t *w = &m->workers[worker_idx];

    /* Create control pipe: [0]=read, [1]=write */
    if (pipe(w->pipe_fd) < 0) {
        syslog(LOG_ERR, "Failed to create control pipe for worker %d: %m", worker_idx);
        return -1;
    }

    /* Set read end to non-blocking for worker */
    if (_pq_set_nonblocking(w->pipe_fd[0]) < 0) {
        syslog(LOG_ERR, "Failed to set pipe non-blocking: %m");
        close(w->pipe_fd[0]);
        close(w->pipe_fd[1]);
        w->pipe_fd[0] = -1;
        w->pipe_fd[1] = -1;
        return -1;
    }

    pid_t child = fork();
    if (child < 0) {
        syslog(LOG_ERR, "Failed to fork worker process: %m");
        close(w->pipe_fd[0]);
        close(w->pipe_fd[1]);
        w->pipe_fd[0] = -1;
        w->pipe_fd[1] = -1;
        return -1;
    }

    if (child == 0) {
        /* Child process (worker) */

        /* Close master's write end and all workers' pipes */
        for (int i = 0; i < m->worker_count; i++) {
            if (m->workers[i].pipe_fd[1] >= 0) {
                close(m->workers[i].pipe_fd[1]);
            }
            if (i != worker_idx && m->workers[i].pipe_fd[0] >= 0) {
                close(m->workers[i].pipe_fd[0]);
            }
        }

        /* Close our own write end; keep read end */
        close(w->pipe_fd[1]);
        w->pipe_fd[1] = -1;

        /* Signal handlers for worker process (use sigaction for portability) */
        {
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;

            sa.sa_handler = _pq_worker_signal_handler;
            sigaction(SIGTERM, &sa, NULL);
            sigaction(SIGINT, &sa, NULL);

            sa.sa_handler = SIG_IGN;
            sigaction(SIGHUP, &sa, NULL);   /* Handled via pipe */

            sa.sa_handler = SIG_DFL;
            sigaction(SIGCHLD, &sa, NULL);
        }

        /* Call worker main (doesn't return on normal exit) */
        exit(pq_worker_main(m->config, m->listen_fd, w->pipe_fd[0]));
    }

    /* Parent process (master) */

    /* Close worker's read end; keep our write end */
    close(w->pipe_fd[0]);
    w->pipe_fd[0] = -1;

    w->pid = child;
    w->state = PQ_WORKER_RUNNING;
    w->started_at = time(NULL);
    w->restart_count++;

    syslog(LOG_INFO, "Forked worker %d (PID %d), restart count: %d",
           worker_idx, child, w->restart_count);

    return 1; /* Parent process continues */
}

/*
 * _pq_master_reap_workers - Reap zombie worker processes
 *
 * Checks for exited workers without blocking (WNOHANG).
 * Updates worker state and schedules restarts if needed.
 *
 * @param m     - Master structure
 * @param block - If 1, use blocking wait (for shutdown); 0 = non-blocking
 */
static void _pq_master_reap_workers(pq_master_t *m, int block) {
    int flags = block ? 0 : WNOHANG;
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, flags)) > 0) {
        /* Find which worker this is */
        int worker_idx = -1;
        for (int i = 0; i < m->worker_count; i++) {
            if (m->workers[i].pid == pid) {
                worker_idx = i;
                break;
            }
        }

        if (worker_idx < 0) {
            syslog(LOG_WARNING, "Reaped unknown PID %d", pid);
            continue;
        }

        pq_worker_info_t *w = &m->workers[worker_idx];
        w->stopped_at = time(NULL);

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code == 0) {
                w->state = PQ_WORKER_STOPPED;
                syslog(LOG_INFO, "Worker %d (PID %d) exited cleanly", worker_idx, pid);
            } else {
                w->state = PQ_WORKER_CRASHED;
                w->last_exit_status = exit_code;
                syslog(LOG_ERR, "Worker %d (PID %d) exited with code %d",
                       worker_idx, pid, exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            w->state = PQ_WORKER_CRASHED;
            w->last_exit_status = -sig;
            syslog(LOG_ERR, "Worker %d (PID %d) terminated by signal %d (%s)",
                   worker_idx, pid, sig, strsignal(sig));
        }
    }

    if (pid < 0 && errno != ECHILD) {
        syslog(LOG_ERR, "waitpid() error: %m");
    }
}

/*
 * _pq_master_restart_workers - Attempt to restart crashed workers
 *
 * Checks each worker slot and restarts crashed/stopped workers if:
 * - Restart count is below max_restarts
 * - Worker didn't crash within crash_timeout of being started
 *
 * @param m - Master structure
 */
static void _pq_master_restart_workers(pq_master_t *m) {
    for (int i = 0; i < m->worker_count; i++) {
        pq_worker_info_t *w = &m->workers[i];

        if (w->state == PQ_WORKER_RUNNING) {
            continue;
        }

        /* Check if we should restart this worker */
        if (w->restart_count >= m->max_restarts) {
            if (w->state != PQ_WORKER_STOPPED) {
                syslog(LOG_ERR, "Worker %d exceeded max restarts (%d), giving up",
                       i, m->max_restarts);
            }
            continue;
        }

        /* Check for crash loop: if worker crashed within crash_timeout of starting */
        time_t uptime = w->stopped_at - w->started_at;
        if (uptime < m->crash_timeout) {
            syslog(LOG_WARNING, "Worker %d crashed after %ld seconds (< %d), escalating backoff",
                   i, uptime, m->crash_timeout);
            w->state = PQ_WORKER_CRASHED; /* Mark for future restart */
            continue; /* Wait before restarting */
        }

        /* Attempt restart */
        syslog(LOG_NOTICE, "Restarting worker %d (attempt %d/%d)",
               i, w->restart_count + 1, m->max_restarts);
        if (_pq_fork_worker(m, i) < 0) {
            syslog(LOG_ERR, "Failed to restart worker %d", i);
        }
    }
}

pq_master_t* pq_master_create(const void *config, int listen_fd, int worker_count) {
    if (!config || listen_fd < 0) {
        return NULL;
    }

    pq_master_t *m = calloc(1, sizeof(pq_master_t));
    if (!m) {
        return NULL;
    }

    /* Determine worker count */
    if (worker_count <= 0) {
        worker_count = _pq_get_cpu_count();
    }

    m->workers = calloc(worker_count, sizeof(pq_worker_info_t));
    if (!m->workers) {
        free(m);
        return NULL;
    }

    /* Initialize worker structures */
    for (int i = 0; i < worker_count; i++) {
        m->workers[i].pid = -1;
        m->workers[i].state = PQ_WORKER_STOPPED;
        m->workers[i].pipe_fd[0] = -1;
        m->workers[i].pipe_fd[1] = -1;
        m->workers[i].restart_count = 0;
        m->workers[i].graceful_timeout = 30;
    }

    m->worker_count = worker_count;
    m->listen_fd = listen_fd;
    m->config = config;
    m->running = 0;
    m->max_restarts = 10;
    m->restart_delay = 2;
    m->crash_timeout = 1;

    return m;
}

void pq_master_destroy(pq_master_t *m) {
    if (!m) {
        return;
    }

    if (m->workers) {
        for (int i = 0; i < m->worker_count; i++) {
            if (m->workers[i].pipe_fd[0] >= 0) {
                close(m->workers[i].pipe_fd[0]);
            }
            if (m->workers[i].pipe_fd[1] >= 0) {
                close(m->workers[i].pipe_fd[1]);
            }
        }
        free(m->workers);
    }

    free(m);
}

int pq_master_run(pq_master_t *m) {
    if (!m || m->listen_fd < 0) {
        return -1;
    }

    /* Set up signal handlers via sigaction (portable, no auto-reset) */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = _pq_master_signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGCHLD, &sa, NULL);

        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, NULL);
    }

    m->running = 1;
    g_master_running = 1;
    g_master_sighup = 0;
    g_master_sigterm = 0;

    syslog(LOG_NOTICE, "Master process starting with %d workers (PID %d)",
           m->worker_count, getpid());

    /* Fork initial workers */
    int fork_failures = 0;
    for (int i = 0; i < m->worker_count; i++) {
        int ret = _pq_fork_worker(m, i);
        if (ret < 0) {
            fork_failures++;
            syslog(LOG_ERR, "Failed to fork initial worker %d", i);
        }
    }

    if (fork_failures == m->worker_count) {
        syslog(LOG_CRIT, "Failed to fork any workers, shutting down");
        m->running = 0;
        return -1;
    }

    /* Main supervision loop */
    time_t last_restart_attempt = 0;

    while (m->running && g_master_running) {
        /* Reap exited workers */
        _pq_master_reap_workers(m, 0);

        /* Handle SIGHUP: reload certificates */
        if (g_master_sighup) {
            g_master_sighup = 0;
            syslog(LOG_NOTICE, "SIGHUP received, reloading certificates in all workers");
            for (int i = 0; i < m->worker_count; i++) {
                _pq_worker_send_control_message(m, i, PQ_CTL_RELOAD);
            }
        }

        /* Handle SIGTERM/SIGINT: graceful shutdown */
        if (g_master_sigterm) {
            syslog(LOG_NOTICE, "Shutdown signal received, initiating graceful shutdown");
            pq_master_shutdown(m);
            break;
        }

        /* Attempt to restart crashed workers (with backoff) */
        time_t now = time(NULL);
        if (now - last_restart_attempt >= m->restart_delay) {
            _pq_master_restart_workers(m);
            last_restart_attempt = now;
        }

        /* Sleep briefly before next iteration */
        sleep(1);
    }

    /* Graceful shutdown: tell workers to stop and give them time to drain */
    syslog(LOG_NOTICE, "Waiting for workers to exit gracefully");
    time_t shutdown_start = time(NULL);
    int timeout = 30; /* 30 seconds graceful shutdown timeout */

    while (time(NULL) - shutdown_start < timeout) {
        _pq_master_reap_workers(m, 0);

        int running_count = 0;
        for (int i = 0; i < m->worker_count; i++) {
            if (m->workers[i].state == PQ_WORKER_RUNNING && m->workers[i].pid > 0) {
                running_count++;
            }
        }

        if (running_count == 0) {
            syslog(LOG_NOTICE, "All workers have exited");
            break;
        }

        sleep(1);
    }

    /* Force-kill any remaining workers */
    for (int i = 0; i < m->worker_count; i++) {
        if (m->workers[i].state == PQ_WORKER_RUNNING && m->workers[i].pid > 0) {
            syslog(LOG_WARNING, "Force-killing worker %d (PID %d)", i, m->workers[i].pid);
            kill(m->workers[i].pid, SIGKILL);
        }
    }

    /* Final reap of all children */
    while (waitpid(-1, NULL, 0) > 0) {
        /* Reap all remaining children */
    }

    syslog(LOG_NOTICE, "Master process exiting");
    return 0;
}

void pq_master_shutdown(pq_master_t *m) {
    if (!m) {
        return;
    }

    syslog(LOG_NOTICE, "Master shutdown initiated, signaling workers");

    for (int i = 0; i < m->worker_count; i++) {
        if (m->workers[i].state == PQ_WORKER_RUNNING) {
            m->workers[i].state = PQ_WORKER_STOPPING;
            _pq_worker_send_control_message(m, i, PQ_CTL_SHUTDOWN);
        }
    }

    m->running = 0;
}

void pq_master_reload(pq_master_t *m) {
    if (!m) {
        return;
    }

    syslog(LOG_NOTICE, "Master reload initiated, signaling workers");

    for (int i = 0; i < m->worker_count; i++) {
        if (m->workers[i].state == PQ_WORKER_RUNNING) {
            _pq_worker_send_control_message(m, i, PQ_CTL_RELOAD);
        }
    }
}

int pq_master_worker_count(const pq_master_t *m) {
    if (!m) {
        return 0;
    }

    int count = 0;
    for (int i = 0; i < m->worker_count; i++) {
        if (m->workers[i].state == PQ_WORKER_RUNNING) {
            count++;
        }
    }
    return count;
}

const pq_worker_info_t* pq_master_get_worker(const pq_master_t *m, int index) {
    if (!m || index < 0 || index >= m->worker_count) {
        return NULL;
    }
    return &m->workers[index];
}

/*
 * Worker process implementation
 */

int pq_worker_main(const void *config, int listen_fd, int control_pipe_rd) {
    if (!config || listen_fd < 0 || control_pipe_rd < 0) {
        return 1;
    }

    /* Signal handlers for this worker (use sigaction for portability) */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        sa.sa_handler = _pq_worker_signal_handler;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);

        sa.sa_handler = SIG_IGN;
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGPIPE, &sa, NULL);

        sa.sa_handler = SIG_DFL;
        sigaction(SIGCHLD, &sa, NULL);
    }

    g_worker_running = 1;

    syslog(LOG_INFO, "Worker process initialized (PID %d)", getpid());

    /*
     * Main worker loop:
     * - Check for control messages from master
     * - Handle connection accept/processing
     * - Check for shutdown/reload signals
     *
     * The actual connection handling is delegated to the connection manager
     * which is registered in the config.
     */

    while (g_worker_running) {
        /* Check for control messages */
        pq_ctl_msg_t ctl_msg;
        int msg_ready = _pq_worker_read_control_message(control_pipe_rd, &ctl_msg);

        if (msg_ready > 0) {
            switch (ctl_msg) {
            case PQ_CTL_RELOAD:
                syslog(LOG_NOTICE, "Worker received reload request");
                /* Call connection manager reload hook */
                /* pq_conn_manager_reload(m->conn_manager); */
                break;

            case PQ_CTL_SHUTDOWN:
                syslog(LOG_INFO, "Worker received shutdown request");
                g_worker_running = 0;
                break;

            case PQ_CTL_STATUS:
                /* Status reporting could be implemented here */
                break;

            default:
                syslog(LOG_WARNING, "Worker received unknown control message %d", ctl_msg);
                break;
            }
        } else if (msg_ready < 0) {
            syslog(LOG_ERR, "Error reading control pipe: %m");
            return 1;
        }

        /* Check for signal-induced shutdown */
        if (!g_worker_running) {
            break;
        }

        /*
         * TODO: Integrate with connection manager
         *
         * The worker should:
         * 1. Call accept() on listen_fd (with timeout or edge-triggered I/O)
         * 2. Process incoming connection via connection manager
         * 3. Periodically check control pipe for shutdown/reload
         *
         * For now, just sleep to prevent busy-loop.
         */
        sleep(1);
    }

    /* Graceful shutdown: drain any remaining connections */
    syslog(LOG_INFO, "Worker shutting down gracefully");

    /* TODO: Implement connection draining from connection manager */

    close(control_pipe_rd);

    syslog(LOG_INFO, "Worker process exiting cleanly");
    return 0;
}
