/**
 * Dashboard page — Real-time monitoring with HUD layout
 */
var DashboardPage = {
    charts: {},
    evtSrc: null,
    prevBytes: -1,
    labels: [],
    connData: [],
    tputData: [],
    MAX_POINTS: 60,
    logLines: 0,
    MAX_LOG: 30,
    upstreams: [],

    render: function() {
        return (
        /* ---- Status Bar ---- */
        '<div class="status-bar" id="statusBar">' +
            '<span class="status-item"><span class="dot green" id="statusDot"></span>' +
            '<span id="statusText">CONNECTED</span></span>' +
            '<span class="status-item">UPTIME: <span id="uptime">0s</span></span>' +
            '<span class="status-item">VER: <span id="srvVersion">—</span></span>' +
            '<span class="status-item">OQS: <span id="oqsStatus">—</span></span>' +
        '</div>' +
        '<div class="shimmer-bar" style="margin-bottom:16px"></div>' +

        /* ---- Stats Row (6 cards) ---- */
        '<div class="hud-stats-row">' +
            '<div class="card hud-scanline"><h3>Active Conn</h3><div class="metric cyan" id="activeConns">0</div></div>' +
            '<div class="card hud-scanline"><h3>Total Conn</h3><div class="metric green" id="totalConns">0</div></div>' +
            '<div class="card hud-scanline"><h3>HS Failures</h3><div class="metric red" id="hsFails">0</div></div>' +
            '<div class="card hud-scanline"><h3>PQ Negotiated</h3><div class="metric purple" id="pqCount">0</div>' +
                '<span class="badge badge-purple">ML-KEM-768</span></div>' +
            '<div class="card hud-scanline"><h3>Classical</h3><div class="metric orange" id="classicalCount">0</div>' +
                '<span class="badge badge-orange">X25519</span></div>' +
            '<div class="card hud-scanline"><h3>Throughput</h3><div class="metric cyan" id="throughput">0 B/s</div></div>' +
        '</div>' +

        /* ---- HUD 3-Column Grid ---- */
        '<div class="hud-grid">' +

            /* LEFT Column */
            '<div class="hud-grid-left">' +
                /* TLS Configuration — real data from API.getConfig() */
                '<div class="hud-panel">' +
                    '<div class="hud-panel-title">TLS Configuration</div>' +
                    '<div id="tlsConfigPanel">' +
                        '<div class="sys-info-row"><span class="sys-info-label">Key Exchange</span><span class="sys-info-value" id="tlsGroups">—</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">TLS Version</span><span class="sys-info-value" id="tlsVersion">—</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">Session Cache</span><span class="sys-info-value" id="tlsSessionCache">—</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">Client Auth</span><span class="sys-info-value" id="tlsClientAuth">—</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">Certificate</span><span class="sys-info-value" id="tlsCertExpiry">—</span></div>' +
                    '</div>' +
                '</div>' +
                /* PQ Adoption — real ratio from SSE data */
                '<div class="hud-panel">' +
                    '<div class="hud-panel-title">PQ Adoption</div>' +
                    '<div style="display:flex;flex-direction:column;align-items:center">' +
                        '<div class="pq-adoption-ring" id="pqRing">' +
                            '<span class="pq-pct" id="pqPct">0%</span>' +
                        '</div>' +
                        '<div style="font-size:0.7em;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-top:8px">Post-Quantum Rate</div>' +
                    '</div>' +
                '</div>' +
                /* System Info — real data from SSE + mgmtStatus */
                '<div class="hud-panel">' +
                    '<div class="hud-panel-title">System Info</div>' +
                    '<div id="sysInfo">' +
                        '<div class="sys-info-row"><span class="sys-info-label">PID</span><span class="sys-info-value" id="sysPid">—</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">Workers</span><span class="sys-info-value" id="sysWorkers">—</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">Rate Limited</span><span class="sys-info-value" id="sysRateLimited">0</span></div>' +
                    '</div>' +
                '</div>' +
            '</div>' +

            /* CENTER Column */
            '<div class="hud-grid-center">' +
                '<div class="chart-container"><h3>Connections Over Time</h3><canvas id="connChart"></canvas></div>' +
                '<div class="chart-container"><h3>Throughput (KB/s)</h3><canvas id="tputChart"></canvas></div>' +
                '<div class="hud-panel">' +
                    '<div class="hud-panel-title">Live Handshake Log</div>' +
                    '<div class="hud-terminal" id="hsLog" style="height:160px;overflow-y:auto"></div>' +
                '</div>' +
            '</div>' +

            /* RIGHT Column */
            '<div class="hud-grid-right">' +
                '<div class="chart-container"><h3>PQ vs Classical</h3><canvas id="pqChart"></canvas></div>' +
                /* Data Transfer — real bytes_in / bytes_out from SSE */
                '<div class="hud-panel">' +
                    '<div class="hud-panel-title">Data Transfer</div>' +
                    '<div id="dataTransferPanel">' +
                        '<div class="sys-info-row"><span class="sys-info-label">Bytes In</span><span class="sys-info-value" id="bytesIn">0 B</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">Bytes Out</span><span class="sys-info-value" id="bytesOut">0 B</span></div>' +
                        '<div class="sys-info-row"><span class="sys-info-label">Total</span><span class="sys-info-value" id="bytesTotal">0 B</span></div>' +
                    '</div>' +
                '</div>' +
                /* Upstream Health — real backend status from API.getConfig() */
                '<div class="hud-panel">' +
                    '<div class="hud-panel-title">Upstream Health</div>' +
                    '<div id="upstreamHealth"><div style="color:var(--text-muted);font-size:0.8em">Loading...</div></div>' +
                '</div>' +
            '</div>' +

        '</div>'
        );
    },

    init: function() {
        var self = this;
        self.labels = [];
        self.connData = [];
        self.tputData = [];
        self.prevBytes = -1;
        self.logLines = 0;

        /* Fetch server info once */
        if (typeof API !== 'undefined' && API.mgmtStatus) {
            API.mgmtStatus().then(function(info) {
                var el = function(id) { return document.getElementById(id); };
                if (el('srvVersion')) el('srvVersion').textContent = info.version || '—';
                if (el('oqsStatus')) el('oqsStatus').textContent = info.oqs_available ? 'ACTIVE' : 'INACTIVE';
                if (el('sysPid')) el('sysPid').textContent = info.pid || '—';
            }).catch(function() {});
        }

        /* Fetch config once — populates TLS config panel + upstream health */
        if (typeof API !== 'undefined' && API.getConfig) {
            API.getConfig().then(function(cfg) {
                if (!cfg) return;
                var el = function(id) { return document.getElementById(id); };

                /* TLS Configuration panel */
                if (cfg.tls) {
                    if (el('tlsGroups')) el('tlsGroups').textContent = cfg.tls.groups || '—';
                    if (el('tlsVersion')) el('tlsVersion').textContent = 'TLS ' + (cfg.tls.min_version || '1.3') + '+';
                    if (el('tlsSessionCache')) el('tlsSessionCache').textContent = cfg.tls.session_cache_size ? cfg.tls.session_cache_size.toLocaleString() : '—';
                    if (el('tlsClientAuth')) el('tlsClientAuth').textContent = cfg.tls.client_auth ? 'REQUIRED' : 'OFF';
                }

                /* Upstream Health panel */
                if (cfg.upstreams && cfg.upstreams.backends) {
                    self.upstreams = cfg.upstreams.backends;
                    self.renderUpstreamHealth();
                }
            }).catch(function() {});
        }

        /* Fetch cert info — populate expiry in TLS panel */
        if (typeof API !== 'undefined' && API.listCerts) {
            API.listCerts().then(function(data) {
                if (!data || !data.active) return;
                var el = document.getElementById('tlsCertExpiry');
                if (!el) return;
                var days = data.active.days_remaining;
                if (days != null) {
                    el.textContent = days + 'd remaining';
                    if (days <= 7) {
                        el.style.color = 'var(--accent-red)';
                    } else if (days <= 30) {
                        el.style.color = 'var(--accent-orange)';
                    } else {
                        el.style.color = 'var(--accent-green)';
                    }
                } else {
                    el.textContent = data.active.not_after || '—';
                }
            }).catch(function() {});
        }

        /* Fetch initial stats */
        API.stats().then(function(d) { self.update(d); }).catch(function() {});

        /* Connection chart — cyan */
        self.charts.conn = new Chart(document.getElementById('connChart'), {
            type: 'line',
            data: { labels: self.labels, datasets: [{
                label: 'Active', data: self.connData,
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6,182,212,0.06)',
                fill: true, tension: 0.4,
                borderWidth: 1.5, pointRadius: 0
            }]},
            options: {
                responsive: true, animation: false,
                maintainAspectRatio: false,
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true,
                        grid: { color: 'rgba(26,26,46,0.8)' },
                        ticks: { color: '#4a5568', font: { family: "'JetBrains Mono', monospace", size: 10 } }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });

        /* PQ vs Classical doughnut — fuchsia / amber */
        self.charts.pq = new Chart(document.getElementById('pqChart'), {
            type: 'doughnut',
            data: {
                labels: ['ML-KEM-768 (PQ)', 'X25519 (Classical)'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ['#d946ef', '#f59e0b'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#8b949e',
                            font: { family: "'JetBrains Mono', monospace", size: 10 },
                            boxWidth: 10,
                            padding: 12
                        }
                    }
                }
            }
        });

        /* Throughput chart — emerald */
        self.charts.tput = new Chart(document.getElementById('tputChart'), {
            type: 'line',
            data: { labels: self.labels, datasets: [{
                label: 'KB/s', data: self.tputData,
                borderColor: '#10b981',
                backgroundColor: 'rgba(16,185,129,0.06)',
                fill: true, tension: 0.4,
                borderWidth: 1.5, pointRadius: 0
            }]},
            options: {
                responsive: true, animation: false,
                maintainAspectRatio: false,
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true,
                        grid: { color: 'rgba(26,26,46,0.8)' },
                        ticks: { color: '#4a5568', font: { family: "'JetBrains Mono', monospace", size: 10 } }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });

        /* Start SSE */
        self.evtSrc = new EventSource('/api/stream');
        self.evtSrc.onmessage = function(e) {
            var d = JSON.parse(e.data);
            self.update(d);
            self.appendHandshakeLine(d);
        };
        self.evtSrc.onerror = function() {
            var dot = document.getElementById('statusDot');
            var txt = document.getElementById('statusText');
            if (dot) dot.className = 'dot red';
            if (txt) txt.textContent = 'DISCONNECTED';
        };
    },

    update: function(d) {
        var el = function(id) { return document.getElementById(id); };

        /* Metric cards */
        if (el('activeConns'))    el('activeConns').textContent = d.active_connections;
        if (el('totalConns'))     el('totalConns').textContent = d.total_connections;
        if (el('hsFails'))        el('hsFails').textContent = d.handshake_failures;
        if (el('pqCount'))        el('pqCount').textContent = d.pq_negotiations || 0;
        if (el('classicalCount')) el('classicalCount').textContent = d.classical_negotiations || 0;

        /* System info */
        if (el('sysWorkers'))     el('sysWorkers').textContent = d.workers || '—';
        if (el('sysRateLimited')) el('sysRateLimited').textContent = d.rate_limited || 0;

        /* Throughput calculation */
        var totalBytes = (d.bytes_in || 0) + (d.bytes_out || 0);
        var rate;
        if (this.prevBytes < 0) {
            this.prevBytes = totalBytes;
            rate = 0;
        } else {
            rate = totalBytes - this.prevBytes;
            this.prevBytes = totalBytes;
        }
        if (el('throughput')) el('throughput').textContent = this.formatBytes(rate);
        if (el('uptime') && d.uptime_seconds != null) el('uptime').textContent = this.formatUptime(d.uptime_seconds * 1000);

        /* Data Transfer panel — live bytes from SSE */
        if (el('bytesIn'))    el('bytesIn').textContent = this.formatBytesTotal(d.bytes_in || 0);
        if (el('bytesOut'))   el('bytesOut').textContent = this.formatBytesTotal(d.bytes_out || 0);
        if (el('bytesTotal')) el('bytesTotal').textContent = this.formatBytesTotal(totalBytes);

        /* PQ Adoption ring */
        var pq = d.pq_negotiations || 0;
        var cl = d.classical_negotiations || 0;
        var total = pq + cl;
        var pct = total > 0 ? Math.round((pq / total) * 100) : 0;
        if (el('pqPct')) el('pqPct').textContent = pct + '%';
        if (el('pqRing')) {
            el('pqRing').style.background = 'conic-gradient(#d946ef 0% ' + pct + '%, #1a1a2e ' + pct + '% 100%)';
        }

        /* Charts */
        var now = new Date().toLocaleTimeString();
        this.labels.push(now);
        this.connData.push(d.active_connections);
        this.tputData.push(rate / 1024);
        if (this.labels.length > this.MAX_POINTS) {
            this.labels.shift();
            this.connData.shift();
            this.tputData.shift();
        }

        if (this.charts.conn) this.charts.conn.update();
        if (this.charts.tput) this.charts.tput.update();
        if (this.charts.pq) {
            this.charts.pq.data.datasets[0].data = [pq, cl];
            this.charts.pq.update();
        }
    },

    /* ---- Handshake Terminal Log ---- */
    appendHandshakeLine: function(d) {
        var log = document.getElementById('hsLog');
        if (!log) return;

        var time = new Date().toLocaleTimeString();
        var line = '<span class="log-time">' + time + '</span> ';

        if (d.handshake_failures > 0 && this._lastHsFails !== d.handshake_failures) {
            line += '<span class="log-warn">[WARN]</span> Handshake failure detected';
            this._lastHsFails = d.handshake_failures;
        } else if (d.rate_limited > 0 && this._lastRateLimited !== d.rate_limited) {
            line += '<span class="log-warn">[WARN]</span> Connection rate-limited';
            this._lastRateLimited = d.rate_limited;
        } else if (d.pq_negotiations > 0 && (d.pq_negotiations !== this._lastPq)) {
            line += '<span class="log-ok">[OK]</span> PQ handshake — ML-KEM-768';
            this._lastPq = d.pq_negotiations;
        } else if (d.active_connections > 0) {
            line += '<span class="log-info">[INFO]</span> Active: ' + d.active_connections +
                    ' | Total: ' + d.total_connections;
        } else {
            line += '<span class="log-info">[INFO]</span> Idle — monitoring';
        }

        var div = document.createElement('div');
        div.innerHTML = line;
        log.appendChild(div);
        this.logLines++;

        if (this.logLines > this.MAX_LOG) {
            log.removeChild(log.firstChild);
            this.logLines--;
        }

        log.scrollTop = log.scrollHeight;
    },

    /* ---- Upstream Health Bars ---- */
    renderUpstreamHealth: function() {
        var container = document.getElementById('upstreamHealth');
        if (!container) return;

        if (!this.upstreams || this.upstreams.length === 0) {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:0.8em;text-transform:uppercase;letter-spacing:1px">No backends configured</div>';
            return;
        }

        var html = '';
        for (var i = 0; i < this.upstreams.length; i++) {
            var b = this.upstreams[i];
            var addr = b.host ? (b.host + ':' + b.port) : (b.address || 'Backend ' + (i + 1));
            var status = b.healthy !== false ? 'healthy' : 'down';
            var pct = b.healthy !== false ? '100' : '0';

            html += '<div class="upstream-bar">' +
                '<span class="upstream-dot ' + status + '"></span>' +
                '<span class="upstream-bar-label">' + addr + '</span>' +
                '<div class="upstream-bar-track"><div class="upstream-bar-fill ' + status + '" style="width:' + pct + '%"></div></div>' +
            '</div>';
        }
        container.innerHTML = html;
    },

    destroy: function() {
        if (this.evtSrc) { this.evtSrc.close(); this.evtSrc = null; }
        Object.keys(this.charts).forEach(function(k) {
            if (DashboardPage.charts[k]) DashboardPage.charts[k].destroy();
        });
        this.charts = {};
        this._lastHsFails = undefined;
        this._lastRateLimited = undefined;
        this._lastPq = undefined;
    },

    formatBytes: function(b) {
        if (b < 1024) return b + ' B/s';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB/s';
        return (b / 1048576).toFixed(1) + ' MB/s';
    },

    formatBytesTotal: function(b) {
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
        return (b / 1073741824).toFixed(2) + ' GB';
    },

    formatUptime: function(ms) {
        var s = Math.floor(ms / 1000);
        var m = Math.floor(s / 60); s %= 60;
        var h = Math.floor(m / 60); m %= 60;
        var d = Math.floor(h / 24); h %= 24;
        if (d > 0) return d + 'd ' + h + 'h';
        if (h > 0) return h + 'h ' + m + 'm';
        return m + 'm ' + s + 's';
    }
};
