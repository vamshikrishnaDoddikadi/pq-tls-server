/**
 * Upstream backend management page
 */
var UpstreamsPage = {
    backends: [],

    render: function() {
        return '<h2 class="page-title">Upstreams</h2>' +
        '<div id="upstreamsContent"><div class="loading">Loading...</div></div>';
    },

    init: function() {
        API.getConfig().then(function(cfg) {
            UpstreamsPage.backends = (cfg.upstreams && cfg.upstreams.backends) || [];
            UpstreamsPage.renderContent(cfg);
        }).catch(function() { Toast.error('Failed to load upstream config'); });
    },

    renderContent: function(cfg) {
        var ups = cfg.upstreams || {};
        var html = '';

        html += '<div class="card mb-4"><div class="card-header">' +
            '<h3>Backends <span class="badge badge-orange">Requires Restart</span></h3>' +
            '<button class="btn btn-sm btn-primary" onclick="UpstreamsPage.addBackend()">Add Backend</button>' +
            '</div><div id="upstreamTable"></div></div>';

        html += '<div class="card mb-4"><h3>Timeouts</h3>' +
            '<div class="grid grid-2">' +
            '<div class="form-group"><label>Connect Timeout (ms)</label>' +
            '<input type="number" id="upConnTimeout" value="' + (ups.connect_timeout_ms || 5000) + '"></div>' +
            '<div class="form-group"><label>Response Timeout (ms)</label>' +
            '<input type="number" id="upRespTimeout" value="' + (ups.timeout_ms || 30000) + '"></div>' +
            '</div></div>';

        html += '<button class="btn btn-primary" onclick="UpstreamsPage.save()">Save Changes</button>';

        document.getElementById('upstreamsContent').innerHTML = html;
        this.renderTable();
    },

    renderTable: function() {
        Table.render('upstreamTable', [
            { key: 'host', label: 'Host' },
            { key: 'port', label: 'Port' },
            { key: 'weight', label: 'Weight' },
            { key: 'use_tls', label: 'TLS', render: function(v) {
                return v ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-blue">No</span>';
            }},
            { key: 'healthy', label: 'Health', render: function(v) {
                return v ? '<span class="dot green"></span>Healthy' : '<span class="dot red"></span>Down';
            }}
        ], this.backends, [
            { label: 'Edit', handler: 'UpstreamsPage.editBackend' },
            { label: 'Delete', handler: 'UpstreamsPage.deleteBackend' }
        ]);
    },

    addBackend: function() {
        Modal.show(
            '<h3>Add Backend</h3>' +
            '<div class="form-group"><label>Host</label>' +
            '<input type="text" id="beHost" placeholder="127.0.0.1"></div>' +
            '<div class="form-group"><label>Port</label>' +
            '<input type="number" id="bePort" value="8080"></div>' +
            '<div class="form-group"><label>Weight (1-100)</label>' +
            '<input type="number" id="beWeight" value="1" min="1" max="100"></div>' +
            '<div class="form-group inline-flex"><label>Use TLS</label>' +
            '<label class="toggle"><input type="checkbox" id="beTls">' +
            '<span class="toggle-slider"></span></label></div>' +
            '<div class="modal-footer">' +
            '<button class="btn" onclick="Modal.hide()">Cancel</button>' +
            '<button class="btn btn-primary" onclick="UpstreamsPage.confirmAdd()">Add</button></div>'
        );
    },

    confirmAdd: function() {
        var host = Form.getValue('beHost');
        var port = Form.getInt('bePort');
        if (!host) { Toast.error('Host is required'); return; }
        if (port < 1 || port > 65535) { Toast.error('Invalid port'); return; }

        this.backends.push({
            host: host,
            port: port,
            weight: Form.getInt('beWeight') || 1,
            use_tls: Form.getValue('beTls'),
            healthy: true
        });
        Modal.hide();
        this.renderTable();
    },

    editBackend: function(idx) {
        var b = UpstreamsPage.backends[idx];
        if (!b) return;

        Modal.show(
            '<h3>Edit Backend</h3>' +
            '<div class="form-group"><label>Host</label>' +
            '<input type="text" id="beHost" value="' + escHtml(b.host) + '"></div>' +
            '<div class="form-group"><label>Port</label>' +
            '<input type="number" id="bePort" value="' + escHtml(b.port) + '"></div>' +
            '<div class="form-group"><label>Weight (1-100)</label>' +
            '<input type="number" id="beWeight" value="' + escHtml(b.weight) + '" min="1" max="100"></div>' +
            '<div class="form-group inline-flex"><label>Use TLS</label>' +
            '<label class="toggle"><input type="checkbox" id="beTls"' +
            (b.use_tls ? ' checked' : '') + '>' +
            '<span class="toggle-slider"></span></label></div>' +
            '<div class="modal-footer">' +
            '<button class="btn" onclick="Modal.hide()">Cancel</button>' +
            '<button class="btn btn-primary" id="beUpdateBtn">Update</button></div>'
        );
        document.getElementById('beUpdateBtn').onclick = function() {
            b.host = Form.getValue('beHost');
            b.port = Form.getInt('bePort');
            b.weight = Form.getInt('beWeight') || 1;
            b.use_tls = Form.getValue('beTls');
            Modal.hide();
            UpstreamsPage.renderTable();
        };
    },

    deleteBackend: function(idx) {
        Modal.confirm('Delete Backend', 'Remove this upstream backend?', function() {
            UpstreamsPage.backends.splice(idx, 1);
            UpstreamsPage.renderTable();
        });
    },

    save: function() {
        API.putUpstreams({
            backends: this.backends.map(function(b) {
                return { host: b.host, port: b.port, weight: b.weight, use_tls: b.use_tls };
            }),
            timeout_ms: Form.getInt('upRespTimeout'),
            connect_timeout_ms: Form.getInt('upConnTimeout')
        }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Saved. Restart required.');
                PQ.showRestartBanner();
            } else {
                Toast.success('Upstream settings saved');
            }
        }).catch(function() { Toast.error('Failed to save'); });
    },

    destroy: function() {}
};
