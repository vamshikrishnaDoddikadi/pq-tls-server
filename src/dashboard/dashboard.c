/**
 * @file dashboard.c
 * @brief Live web dashboard with embedded HTML and SSE streaming
 * @author Vamshi Krishna Doddikadi
 */

#include "dashboard.h"
#include "../metrics/prometheus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <stdatomic.h>
#include <time.h>

static pthread_t dashboard_thread;
static atomic_int dashboard_running = 0;
static pq_conn_manager_t *g_mgr = NULL;
static int g_port = 0;

/* ======================================================================== */
/* Embedded HTML Dashboard                                                  */
/* ======================================================================== */

static const char *DASHBOARD_HTML =
"<!DOCTYPE html>\n"
"<html lang=\"en\"><head><meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>PQ-TLS Server Dashboard</title>\n"
"<style>\n"
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
"background:#0f1117;color:#e1e4e8;padding:20px}\n"
"h1{text-align:center;margin-bottom:8px;font-size:1.8em;"
"background:linear-gradient(90deg,#58a6ff,#bc8cff);-webkit-background-clip:text;"
"-webkit-text-fill-color:transparent}\n"
".subtitle{text-align:center;color:#8b949e;margin-bottom:24px;font-size:.9em}\n"
".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));"
"gap:16px;margin-bottom:20px}\n"
".card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px}\n"
".card h3{color:#8b949e;font-size:.85em;text-transform:uppercase;letter-spacing:1px;"
"margin-bottom:8px}\n"
".metric{font-size:2.2em;font-weight:700}\n"
".metric.green{color:#3fb950}\n"
".metric.blue{color:#58a6ff}\n"
".metric.purple{color:#bc8cff}\n"
".metric.orange{color:#d29922}\n"
".metric.red{color:#f85149}\n"
".chart-container{background:#161b22;border:1px solid #30363d;border-radius:12px;"
"padding:20px;margin-bottom:20px}\n"
".chart-container h3{color:#8b949e;font-size:.85em;text-transform:uppercase;"
"letter-spacing:1px;margin-bottom:12px}\n"
"canvas{width:100%!important;height:200px!important}\n"
".pq-badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:.8em;"
"font-weight:600;margin-top:4px}\n"
".pq-badge.active{background:#1f3a1f;color:#3fb950;border:1px solid #238636}\n"
".pq-badge.fallback{background:#3a2f1f;color:#d29922;border:1px solid #9e6a03}\n"
".status-bar{display:flex;gap:12px;justify-content:center;margin-bottom:20px;"
"flex-wrap:wrap}\n"
".status-item{padding:6px 16px;border-radius:8px;font-size:.85em;"
"background:#161b22;border:1px solid #30363d}\n"
".status-item .dot{display:inline-block;width:8px;height:8px;border-radius:50%;"
"margin-right:6px}\n"
".dot.green{background:#3fb950}\n"
".dot.red{background:#f85149}\n"
"</style>\n"
"<script src=\"https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js\"></script>\n"
"</head><body>\n"
"<h1>PQ-TLS Server Dashboard</h1>\n"
"<p class=\"subtitle\">Post-Quantum TLS Termination Proxy &mdash; Real-time Monitoring</p>\n"
"\n"
"<div class=\"status-bar\" id=\"statusBar\">\n"
"  <span class=\"status-item\"><span class=\"dot green\" id=\"statusDot\"></span>"
"<span id=\"statusText\">Connected</span></span>\n"
"  <span class=\"status-item\">Uptime: <span id=\"uptime\">0s</span></span>\n"
"</div>\n"
"\n"
"<div class=\"grid\">\n"
"  <div class=\"card\"><h3>Active Connections</h3>"
"<div class=\"metric blue\" id=\"activeConns\">0</div></div>\n"
"  <div class=\"card\"><h3>Total Connections</h3>"
"<div class=\"metric green\" id=\"totalConns\">0</div></div>\n"
"  <div class=\"card\"><h3>Handshake Failures</h3>"
"<div class=\"metric red\" id=\"hsFails\">0</div></div>\n"
"  <div class=\"card\"><h3>PQ Negotiations</h3>"
"<div class=\"metric purple\" id=\"pqCount\">0</div>"
"<span class=\"pq-badge active\" id=\"pqBadge\">ML-KEM-768</span></div>\n"
"  <div class=\"card\"><h3>Classical Fallbacks</h3>"
"<div class=\"metric orange\" id=\"classicalCount\">0</div>"
"<span class=\"pq-badge fallback\">X25519</span></div>\n"
"  <div class=\"card\"><h3>Throughput</h3>"
"<div class=\"metric blue\" id=\"throughput\">0 B/s</div></div>\n"
"</div>\n"
"\n"
"<div class=\"grid\">\n"
"  <div class=\"chart-container\"><h3>Connections Over Time</h3>"
"<canvas id=\"connChart\"></canvas></div>\n"
"  <div class=\"chart-container\"><h3>PQ vs Classical Negotiation</h3>"
"<canvas id=\"pqChart\"></canvas></div>\n"
"</div>\n"
"<div class=\"chart-container\"><h3>Throughput (KB/s)</h3>"
"<canvas id=\"tputChart\"></canvas></div>\n"
"\n"
"<script>\n"
"const MAX_POINTS=60;\n"
"let labels=[], connData=[], tputData=[], prevBytes=0, startTime=Date.now();\n"
"\n"
"const connChart=new Chart(document.getElementById('connChart'),{\n"
"  type:'line',data:{labels,datasets:[{label:'Active',data:connData,"
"borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.1)',fill:true,tension:.3}]},"
"  options:{responsive:true,animation:false,scales:{"
"x:{display:false},y:{beginAtZero:true,grid:{color:'#21262d'},ticks:{color:'#8b949e'}}},"
"plugins:{legend:{display:false}}}\n"
"});\n"
"\n"
"const pqChart=new Chart(document.getElementById('pqChart'),{\n"
"  type:'doughnut',data:{labels:['ML-KEM-768 (PQ)','X25519 (Classical)'],"
"datasets:[{data:[0,0],backgroundColor:['#bc8cff','#d29922'],borderWidth:0}]},"
"  options:{responsive:true,plugins:{legend:{labels:{color:'#e1e4e8'}}}}\n"
"});\n"
"\n"
"const tputChart=new Chart(document.getElementById('tputChart'),{\n"
"  type:'line',data:{labels,datasets:[{label:'KB/s',data:tputData,"
"borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.1)',fill:true,tension:.3}]},"
"  options:{responsive:true,animation:false,scales:{"
"x:{display:false},y:{beginAtZero:true,grid:{color:'#21262d'},ticks:{color:'#8b949e'}}},"
"plugins:{legend:{display:false}}}\n"
"});\n"
"\n"
"function formatBytes(b){if(b<1024)return b+' B/s';"
"if(b<1048576)return(b/1024).toFixed(1)+' KB/s';"
"return(b/1048576).toFixed(1)+' MB/s'}\n"
"\n"
"function formatUptime(ms){let s=Math.floor(ms/1000);"
"let m=Math.floor(s/60);s%%=60;let h=Math.floor(m/60);m%%=60;"
"let d=Math.floor(h/24);h%%=24;"
"if(d>0)return d+'d '+h+'h';if(h>0)return h+'h '+m+'m';return m+'m '+s+'s'}\n"
"\n"
"const evtSrc=new EventSource('/api/stream');\n"
"evtSrc.onmessage=function(e){\n"
"  const d=JSON.parse(e.data);\n"
"  document.getElementById('activeConns').textContent=d.active_connections;\n"
"  document.getElementById('totalConns').textContent=d.total_connections;\n"
"  document.getElementById('hsFails').textContent=d.handshake_failures;\n"
"  document.getElementById('pqCount').textContent=d.pq_negotiations||0;\n"
"  document.getElementById('classicalCount').textContent=d.classical_negotiations||0;\n"
"  document.getElementById('uptime').textContent=formatUptime(Date.now()-startTime);\n"
"  let totalBytes=d.bytes_in+d.bytes_out;\n"
"  let rate=totalBytes-prevBytes;prevBytes=totalBytes;\n"
"  document.getElementById('throughput').textContent=formatBytes(rate);\n"
"\n"
"  let now=new Date().toLocaleTimeString();\n"
"  labels.push(now);connData.push(d.active_connections);tputData.push(rate/1024);\n"
"  if(labels.length>MAX_POINTS){labels.shift();connData.shift();tputData.shift()}\n"
"  connChart.update();tputChart.update();\n"
"  pqChart.data.datasets[0].data=[d.pq_negotiations||0,d.classical_negotiations||0];\n"
"  pqChart.update();\n"
"};\n"
"evtSrc.onerror=function(){\n"
"  document.getElementById('statusDot').className='dot red';\n"
"  document.getElementById('statusText').textContent='Disconnected';\n"
"};\n"
"</script>\n"
"</body></html>\n";

/* ======================================================================== */
/* HTTP Response Helpers                                                    */
/* ======================================================================== */

static void send_response(int fd, const char *status, const char *content_type,
                          const char *body, size_t body_len) {
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        status, content_type, body_len);
    send(fd, header, (size_t)hlen, MSG_NOSIGNAL);
    if (body && body_len > 0)
        send(fd, body, body_len, MSG_NOSIGNAL);
}

static void send_json_stats(int fd, pq_conn_manager_t *mgr) {
    char buf[2048];
    pq_conn_manager_metrics_json(mgr, buf, sizeof(buf));
    send_response(fd, "200 OK", "application/json", buf, strlen(buf));
}

/* Per-SSE-client context for threaded streaming */
typedef struct {
    int fd;
    pq_conn_manager_t *mgr;
} sse_ctx_t;

static void* sse_thread_fn(void *arg) {
    sse_ctx_t *ctx = (sse_ctx_t *)arg;
    int fd = ctx->fd;
    pq_conn_manager_t *mgr = ctx->mgr;
    free(ctx);

    /* Send SSE headers */
    const char *headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: keep-alive\r\n\r\n";
    send(fd, headers, strlen(headers), MSG_NOSIGNAL);

    /* Stream metrics every second until client disconnects or server stops */
    while (atomic_load(&dashboard_running)) {
        char buf[2048];
        pq_conn_manager_metrics_json(mgr, buf, sizeof(buf));

        char event[2200];
        int n = snprintf(event, sizeof(event), "data: %s\n\n", buf);
        if (n < 0 || n >= (int)sizeof(event)) break;
        ssize_t sent = send(fd, event, (size_t)n, MSG_NOSIGNAL);
        if (sent <= 0) break; /* Client disconnected */

        usleep(1000000);
    }

    close(fd);
    return NULL;
}

/* ======================================================================== */
/* HTTP Request Router                                                      */
/* ======================================================================== */

static void handle_dashboard_request(int fd, pq_conn_manager_t *mgr) {
    char req[4096];
    ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
    if (n <= 0) { close(fd); return; }
    req[n] = '\0';

    /* Parse request path — validate sscanf parsed both fields */
    char method[16] = {0}, path[256] = {0};
    if (sscanf(req, "%15s %255s", method, path) < 2) {
        close(fd);
        return;
    }

    if (strcmp(path, "/") == 0 || strcmp(path, "/dashboard") == 0) {
        send_response(fd, "200 OK", "text/html; charset=utf-8",
                      DASHBOARD_HTML, strlen(DASHBOARD_HTML));
        close(fd);
    }
    else if (strcmp(path, "/api/stats") == 0) {
        send_json_stats(fd, mgr);
        close(fd);
    }
    else if (strcmp(path, "/api/stream") == 0) {
        /* SSE — hand off to a dedicated thread so the dashboard thread
           stays responsive for health checks and other requests. */
        sse_ctx_t *ctx = malloc(sizeof(sse_ctx_t));
        if (ctx) {
            ctx->fd = fd;
            ctx->mgr = mgr;
            pthread_t t;
            if (pthread_create(&t, NULL, sse_thread_fn, ctx) == 0) {
                pthread_detach(t);
                /* fd ownership transferred to SSE thread */
            } else {
                free(ctx);
                close(fd);
            }
        } else {
            close(fd);
        }
    }
    else if (strcmp(path, "/metrics") == 0) {
        char buf[4096];
        pq_prometheus_format(mgr, buf, sizeof(buf));
        send_response(fd, "200 OK",
                      "text/plain; version=0.0.4; charset=utf-8",
                      buf, strlen(buf));
        close(fd);
    }
    else if (strcmp(path, "/health") == 0) {
        const char *ok = "{\"status\":\"ok\"}";
        send_response(fd, "200 OK", "application/json", ok, strlen(ok));
        close(fd);
    }
    else {
        const char *msg = "404 Not Found";
        send_response(fd, "404 Not Found", "text/plain", msg, strlen(msg));
        close(fd);
    }
}

/* ======================================================================== */
/* Dashboard Thread                                                         */
/* ======================================================================== */

static void* dashboard_thread_fn(void *arg) {
    (void)arg;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)g_port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, 32) < 0) {
        close(fd);
        return NULL;
    }

    while (atomic_load(&dashboard_running)) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;

        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) continue;

        /* Handle requests inline — dashboard traffic is light enough
         * that blocking on SSE streams is acceptable since the
         * main TLS proxy runs on separate threads */
        handle_dashboard_request(cfd, g_mgr);
    }

    close(fd);
    return NULL;
}

/* ======================================================================== */
/* Public API                                                               */
/* ======================================================================== */

int pq_dashboard_start(pq_conn_manager_t *mgr, int port) {
    if (port <= 0) return 0; /* Disabled */

    g_mgr = mgr;
    g_port = port;
    atomic_store(&dashboard_running, 1);

    if (pthread_create(&dashboard_thread, NULL, dashboard_thread_fn, NULL) != 0) {
        return -1;
    }
    pthread_detach(dashboard_thread);
    return 0;
}

void pq_dashboard_stop(void) {
    atomic_store(&dashboard_running, 0);
}
