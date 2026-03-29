/**
 * Server settings page
 */
var SettingsPage = {
    render: function() {
        return '<h2 class="page-title">Settings</h2>' +
        '<div id="settingsContent"><div class="loading">Loading...</div></div>';
    },

    init: function() {
        API.getConfig().then(function(cfg) {
            SettingsPage.renderContent(cfg);
        }).catch(function() { Toast.error('Failed to load settings'); });
    },

    renderContent: function(cfg) {
        var listen = cfg.listen || {};
        var server = cfg.server || {};
        var logging = cfg.logging || {};
        var health = cfg.health || {};
        var html = '';

        /* Listen */
        html += '<div class="card mb-4">' +
            '<h3>Listen <span class="badge badge-orange">Requires Restart</span></h3>' +
            '<div class="grid grid-2">' +
            '<div class="form-group"><label>Bind Address</label>' +
            '<input type="text" id="srvAddress" value="' + escHtml(listen.address || '0.0.0.0') + '"></div>' +
            '<div class="form-group"><label>Port</label>' +
            '<input type="number" id="srvPort" value="' + (listen.port || 8443) + '"></div>' +
            '</div>' +
            '<button class="btn btn-primary" onclick="SettingsPage.saveListen()">Save</button></div>';

        /* Workers */
        html += '<div class="card mb-4">' +
            '<h3>Workers <span class="badge badge-orange">Requires Restart</span></h3>' +
            '<div class="grid grid-2">' +
            '<div class="form-group"><label>Worker Count (0=auto)</label>' +
            '<input type="number" id="srvWorkers" value="' + (server.workers || 0) + '" min="0"></div>' +
            '<div class="form-group"><label>Max Connections</label>' +
            '<input type="number" id="srvMaxConns" value="' + (server.max_connections || 1024) + '"></div>' +
            '</div>' +
            '<button class="btn btn-primary" onclick="SettingsPage.saveServer()">Save</button></div>';

        /* Logging */
        html += '<div class="card mb-4"><h3>Logging</h3>' +
            '<div class="grid grid-2">' +
            '<div class="form-group"><label>Log Level <span class="badge badge-green">Runtime</span></label>' +
            '<select id="srvLogLevel">' +
            '<option value="debug"' + (logging.level === 'debug' ? ' selected' : '') + '>Debug</option>' +
            '<option value="info"' + (logging.level === 'info' ? ' selected' : '') + '>Info</option>' +
            '<option value="warn"' + (logging.level === 'warn' ? ' selected' : '') + '>Warn</option>' +
            '<option value="error"' + (logging.level === 'error' ? ' selected' : '') + '>Error</option>' +
            '</select></div>' +
            '<div class="form-group"><label>Log File</label>' +
            '<input type="text" id="srvLogFile" value="' + escHtml(logging.file || '') + '" placeholder="stderr"></div>' +
            '</div>' +
            '<div class="grid grid-2">' +
            '<div class="form-group inline-flex"><label>Access Log</label>' +
            '<label class="toggle"><input type="checkbox" id="srvAccessLog"' +
            (logging.access_log ? ' checked' : '') + '>' +
            '<span class="toggle-slider"></span></label></div>' +
            '<div class="form-group inline-flex"><label>JSON Logging</label>' +
            '<label class="toggle"><input type="checkbox" id="srvJsonLog"' +
            (logging.json ? ' checked' : '') + '>' +
            '<span class="toggle-slider"></span></label></div>' +
            '</div>' +
            '<button class="btn btn-primary" onclick="SettingsPage.saveLogging()">Save</button></div>';

        /* Process info */
        html += '<div class="card mb-4"><h3>Process</h3>' +
            '<p class="text-secondary">Dashboard port: ' + escHtml(health.port || 'disabled') + '</p>' +
            '<p class="text-secondary">Daemonize: ' + (server.daemonize ? 'yes' : 'no') + '</p>' +
            '<p class="text-secondary">PID file: ' + escHtml(server.pid_file || 'none') + '</p>' +
            '</div>';

        /* Restart button */
        html += '<div class="card">' +
            '<h3>Server Control</h3>' +
            '<p class="text-secondary mb-4">Restart the server to apply pending configuration changes.</p>' +
            '<button class="btn btn-danger" onclick="SettingsPage.restartServer()">Restart Server</button>' +
            '</div>';

        document.getElementById('settingsContent').innerHTML = html;
    },

    saveListen: function() {
        if (!Form.validatePort('srvPort')) return;
        API.putListen({
            address: Form.getValue('srvAddress'),
            port: Form.getInt('srvPort')
        }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Saved. Restart required.');
                PQ.showRestartBanner();
            } else {
                Toast.success('Listen settings saved');
            }
        }).catch(function() { Toast.error('Failed to save'); });
    },

    saveServer: function() {
        API.putServer({
            workers: Form.getInt('srvWorkers'),
            max_connections: Form.getInt('srvMaxConns')
        }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Saved. Restart required.');
                PQ.showRestartBanner();
            } else {
                Toast.success('Server settings saved');
            }
        }).catch(function() { Toast.error('Failed to save'); });
    },

    saveLogging: function() {
        API.putLogging({
            level: Form.getValue('srvLogLevel'),
            file: Form.getValue('srvLogFile'),
            access_log: Form.getValue('srvAccessLog'),
            json: Form.getValue('srvJsonLog')
        }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Saved. Restart required for some changes.');
                PQ.showRestartBanner();
            } else {
                Toast.success('Logging settings applied');
            }
        }).catch(function() { Toast.error('Failed to save'); });
    },

    restartServer: function() {
        PQ.restartServer();
    },

    destroy: function() {}
};
