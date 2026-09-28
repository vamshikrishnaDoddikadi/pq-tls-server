/*
 * test_master_worker.c - Tests for worker restart backoff
 *
 * The restart policy lives in static functions, so this test includes the
 * implementation directly. Do NOT also add src/core/master_worker.c to the
 * test executable's sources (it would define every symbol twice).
 *
 * Regression: a worker that crashed within crash_timeout of starting was
 * never restarted, because the "backoff" re-checked the same stale
 * stopped_at - started_at uptime on every pass.
 */

#include "../src/core/master_worker.c"

#include <stdio.h>
#include <stdlib.h>

#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

#define PASS(name) printf("PASS: %s\n", name)

static void init_master(pq_master_t *m, pq_worker_info_t *w)
{
    memset(m, 0, sizeof(*m));
    memset(w, 0, sizeof(*w));
    m->workers = w;
    m->worker_count = 1;
    m->max_restarts = 10;
    m->restart_delay = 2;
    m->crash_timeout = 1;
    m->running = 1;
    w->pid = 4242;
    w->pipe_fd[0] = -1;
    w->pipe_fd[1] = -1;
}

/* Test: a worker that crashed instantly is restarted after restart_delay */
TEST(test_fast_crash_is_restarted) {
    pq_master_t m;
    pq_worker_info_t w;
    init_master(&m, &w);

    w.state = PQ_WORKER_CRASHED;
    w.started_at = 1000;
    w.stopped_at = 1000;      /* uptime 0 < crash_timeout */
    w.restart_count = 0;

    ASSERT(!_pq_worker_restart_due(&m, &w, 1000));
    ASSERT(!_pq_worker_restart_due(&m, &w, 1001));
    ASSERT(_pq_worker_restart_due(&m, &w, 1002));
    /* ...and stays due (previously it was skipped forever) */
    ASSERT(_pq_worker_restart_due(&m, &w, 5000));

    PASS("test_fast_crash_is_restarted");
}

/* Test: delay doubles per restart and is capped at restart_delay << 6 */
TEST(test_backoff_is_exponential_and_capped) {
    pq_master_t m;
    pq_worker_info_t w;
    init_master(&m, &w);

    w.state = PQ_WORKER_CRASHED;
    w.started_at = 100;
    w.stopped_at = 500;

    for (int n = 0; n <= 12; n++) {
        int shift = n > 6 ? 6 : n;
        time_t delay = (time_t)m.restart_delay << shift;
        w.restart_count = n;
        ASSERT(!_pq_worker_restart_due(&m, &w, w.stopped_at + delay - 1));
        ASSERT(_pq_worker_restart_due(&m, &w, w.stopped_at + delay));
    }

    /* Never-started slot (initial fork failed) is due immediately */
    memset(&w, 0, sizeof(w));
    w.state = PQ_WORKER_STOPPED;
    ASSERT(_pq_worker_restart_due(&m, &w, 1));

    PASS("test_backoff_is_exponential_and_capped");
}

/* Test: restart pass does not fork while backing off or past max_restarts */
TEST(test_restart_pass_respects_backoff_and_limit) {
    pq_master_t m;
    pq_worker_info_t w;
    init_master(&m, &w);

    /* Just crashed: backoff (restart_delay << 3 = 16 s) not yet elapsed */
    w.state = PQ_WORKER_CRASHED;
    w.restart_count = 3;
    w.started_at = _pq_now();
    w.stopped_at = w.started_at;
    _pq_master_restart_workers(&m);
    ASSERT(w.pid == 4242);
    ASSERT(w.state == PQ_WORKER_CRASHED);
    ASSERT(w.restart_count == 3);

    /* Out of restarts: never restarted, however long ago it stopped */
    w.restart_count = m.max_restarts;
    w.stopped_at = 1;
    w.started_at = 1;
    _pq_master_restart_workers(&m);
    ASSERT(w.pid == 4242);
    ASSERT(w.state == PQ_WORKER_CRASHED);
    ASSERT(w.restart_count == m.max_restarts);

    PASS("test_restart_pass_respects_backoff_and_limit");
}

int run_master_worker_tests(void) {
    test_fast_crash_is_restarted();
    test_backoff_is_exponential_and_capped();
    test_restart_pass_respects_backoff_and_limit();
    return 0;
}
