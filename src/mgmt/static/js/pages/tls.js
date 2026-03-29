/**
 * TLS / SSL configuration page
 */
var TlsPage = {
    render: function() {
        return '<h2 class="page-title">TLS / SSL</h2>' +
        '<div id="tlsContent"><div class="loading">Loading...</div></div>';
    },

    init: function() {
        API.getConfig().then(function(cfg) {
            TlsPage.renderContent(cfg);
        }).catch(function() { Toast.error('Failed to load TLS config'); });
    },

    renderContent: function(cfg) {
        var tls = cfg.tls || {};
        var html = '';

        /* Certificate card */
        html += '<div class="card mb-4">' +
            '<div class="card-header"><h3>Current Certificate</h3>' +
            '<div class="btn-group">' +
            '<button class="btn btn-sm" onclick="TlsPage.reloadCerts()">Reload Certs</button>' +
            '</div></div>' +
            '<div class="form-group"><label>Certificate File</label>' +
            '<input type="text" id="tlsCert" value="' + escHtml(tls.cert || '') + '"></div>' +
            '<div class="form-group"><label>Private Key File</label>' +
            '<input type="text" id="tlsKey" value="' + escHtml(tls.key || '') + '"></div>' +
            '<div class="form-group"><label>CA File (client auth)</label>' +
            '<input type="text" id="tlsCa" value="' + escHtml(tls.ca || '') + '"></div>' +
            '<div class="form-group inline-flex">' +
            '<label>Require Client Auth</label>' +
            '<label class="toggle"><input type="checkbox" id="tlsClientAuth"' +
            (tls.client_auth ? ' checked' : '') + '>' +
            '<span class="toggle-slider"></span></label></div>' +
            '</div>';

        /* Protocol settings */
        html += '<div class="card mb-4">' +
            '<h3>Protocol Settings <span class="badge badge-orange">Requires Restart</span></h3>' +
            '<div class="form-group"><label>Key Exchange Groups</label>' +
            '<input type="text" id="tlsGroups" value="' + escHtml(tls.groups || '') + '">' +
            '<p class="text-muted mt-2">Colon-separated. e.g. X25519MLKEM768:X25519</p></div>' +
            '<div class="form-group"><label>Minimum TLS Version</label>' +
            '<select id="tlsMinVer">' +
            '<option value="1.3"' + (tls.min_version === '1.3' ? ' selected' : '') + '>TLS 1.3</option>' +
            '<option value="1.2"' + (tls.min_version === '1.2' ? ' selected' : '') + '>TLS 1.2</option>' +
            '</select></div>' +
            '<div class="form-group"><label>Session Cache Size</label>' +
            '<input type="number" id="tlsSessionCache" value="' + (tls.session_cache_size || 0) + '">' +
            '</div></div>';

        /* Save button */
        html += '<div class="btn-group">' +
            '<button class="btn btn-primary" onclick="TlsPage.save()">Save Changes</button>' +
            '</div>';

        document.getElementById('tlsContent').innerHTML = html;
    },

    save: function() {
        API.putTls({
            cert: Form.getValue('tlsCert'),
            key: Form.getValue('tlsKey'),
            ca: Form.getValue('tlsCa'),
            client_auth: Form.getValue('tlsClientAuth'),
            groups: Form.getValue('tlsGroups'),
            min_version: Form.getValue('tlsMinVer'),
            session_cache_size: Form.getInt('tlsSessionCache')
        }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Saved. Restart required to apply changes.');
                PQ.showRestartBanner();
            } else {
                Toast.success('TLS settings saved');
            }
        }).catch(function() { Toast.error('Failed to save TLS settings'); });
    },

    reloadCerts: function() {
        API.reloadTls().then(function(r) {
            if (r.status === 'ok') Toast.success('Certificates reloaded');
            else Toast.error('Reload failed');
        }).catch(function() { Toast.error('Reload failed'); });
    },

    destroy: function() {}
};
