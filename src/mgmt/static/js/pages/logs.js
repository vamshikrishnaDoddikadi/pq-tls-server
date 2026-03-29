/**
 * Real-time log viewer page
 */
var LogsPage = {
    evtSrc: null,
    autoScroll: true,
    paused: false,
    filterLevel: { DEBUG: true, INFO: true, WARN: true, ERROR: true },
    searchText: '',

    render: function() {
        return '<h2 class="page-title">Logs</h2>' +
        '<div class="card mb-4">' +
        '<div class="card-header" style="flex-wrap:wrap;gap:8px">' +
        '<div class="inline-flex" style="gap:12px">' +
        '<label style="font-size:0.85em"><input type="checkbox" id="logDebug" checked onchange="LogsPage.toggleFilter(\'DEBUG\')"> DEBUG</label>' +
        '<label style="font-size:0.85em"><input type="checkbox" id="logInfo" checked onchange="LogsPage.toggleFilter(\'INFO\')"> INFO</label>' +
        '<label style="font-size:0.85em"><input type="checkbox" id="logWarn" checked onchange="LogsPage.toggleFilter(\'WARN\')"> WARN</label>' +
        '<label style="font-size:0.85em"><input type="checkbox" id="logError" checked onchange="LogsPage.toggleFilter(\'ERROR\')"> ERROR</label>' +
        '</div>' +
        '<div class="inline-flex" style="gap:8px">' +
        '<input type="text" id="logSearch" placeholder="Filter..." style="width:180px" oninput="LogsPage.updateSearch()">' +
        '<button class="btn btn-sm" id="logPauseBtn" onclick="LogsPage.togglePause()">Pause</button>' +
        '<label style="font-size:0.85em"><input type="checkbox" id="logAutoScroll" checked onchange="LogsPage.autoScroll=this.checked"> Auto-scroll</label>' +
        '<button class="btn btn-sm" onclick="LogsPage.downloadLogs()">Download</button>' +
        '</div></div>' +
        '<div id="logViewer" style="background:var(--bg-primary);border:1px solid var(--border);' +
        'border-radius:6px;height:500px;overflow-y:auto;padding:12px;font-family:\'Consolas\',\'Monaco\',monospace;' +
        'font-size:0.8em;line-height:1.6;white-space:pre-wrap;word-break:break-all"></div>' +
        '</div>';
    },

    init: function() {
        var self = this;

        /* Load recent logs first */
        API.logsRecent(200).then(function(logs) {
            if (Array.isArray(logs)) {
                logs.forEach(function(entry) {
                    self.appendEntry(entry);
                });
            }
        }).catch(function() {});

        /* Connect SSE for live streaming */
        self.evtSrc = new EventSource('/api/logs/stream?token=' + API.getToken());
        self.evtSrc.onmessage = function(e) {
            if (self.paused) return;
            try {
                self.appendEntry(JSON.parse(e.data));
            } catch(ex) { /* ignore parse errors */ }
        };
        self.evtSrc.onerror = function() {
            self.appendLine('--- Log stream disconnected ---', 'ERROR');
        };
    },

    appendEntry: function(entry) {
        if (!entry || !entry.level) return;
        if (!this.filterLevel[entry.level]) return;

        var msg = entry.msg || '';
        if (this.searchText && msg.toLowerCase().indexOf(this.searchText) === -1) return;

        var text = '[' + (entry.ts || '') + '] [' + entry.level + '] ' + msg;
        this.appendLine(text, entry.level);
    },

    appendLine: function(text, level) {
        var viewer = document.getElementById('logViewer');
        if (!viewer) return;

        var line = document.createElement('div');
        line.textContent = text;

        switch (level) {
        case 'ERROR': line.style.color = 'var(--accent-red)'; break;
        case 'WARN':  line.style.color = 'var(--accent-orange)'; break;
        case 'DEBUG': line.style.color = 'var(--text-muted)'; break;
        default:      line.style.color = 'var(--text-secondary)'; break;
        }

        viewer.appendChild(line);

        /* Limit lines */
        while (viewer.children.length > 1000) {
            viewer.removeChild(viewer.firstChild);
        }

        if (this.autoScroll) {
            viewer.scrollTop = viewer.scrollHeight;
        }
    },

    toggleFilter: function(level) {
        this.filterLevel[level] = document.getElementById('log' + level.charAt(0) + level.slice(1).toLowerCase()).checked;
    },

    updateSearch: function() {
        this.searchText = (Form.getValue('logSearch') || '').toLowerCase();
    },

    togglePause: function() {
        this.paused = !this.paused;
        var btn = document.getElementById('logPauseBtn');
        if (btn) btn.textContent = this.paused ? 'Resume' : 'Pause';
    },

    downloadLogs: function() {
        var viewer = document.getElementById('logViewer');
        if (!viewer) return;
        var text = viewer.innerText;
        var blob = new Blob([text], { type: 'text/plain' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'pq-tls-server-logs.txt';
        a.click();
        URL.revokeObjectURL(url);
    },

    destroy: function() {
        if (this.evtSrc) { this.evtSrc.close(); this.evtSrc = null; }
    }
};
