/**
 * Certificate management page
 */
var CertificatesPage = {
    render: function() {
        return '<h2 class="page-title">Certificates</h2>' +
        '<div id="certsContent"><div class="loading">Loading...</div></div>';
    },

    init: function() {
        this.load().catch(function() {});
    },

    load: function() {
        return API.listCerts().then(function(data) {
            CertificatesPage.renderContent(data);
        }).catch(function() {
            document.getElementById('certsContent').innerHTML =
                '<p class="text-secondary">Failed to load certificates.</p>';
        });
    },

    renderContent: function(data) {
        var html = '';

        /* Active certificate */
        if (data.active) {
            var a = data.active;
            var expiryClass = a.days_remaining < 7 ? 'badge-red' :
                              (a.days_remaining < 30 ? 'badge-orange' : 'badge-green');
            html += '<div class="card mb-4"><div class="card-header">' +
                '<h3>Active Server Certificate</h3>' +
                '<span class="badge ' + expiryClass + '">' + a.days_remaining + ' days remaining</span></div>' +
                '<div class="grid grid-2">' +
                '<div><p class="text-secondary">Subject</p><p>' + escHtml(a.subject) + '</p></div>' +
                '<div><p class="text-secondary">Issuer</p><p>' + escHtml(a.issuer) + '</p></div>' +
                '<div><p class="text-secondary">Key Type</p><p>' + escHtml(a.key_type) + '</p></div>' +
                '<div><p class="text-secondary">Expires</p><p>' + escHtml(a.not_after) + '</p></div>' +
                '<div><p class="text-secondary">Algorithm</p><p>' + escHtml(a.sig_algo || '') + '</p></div>' +
                '<div><p class="text-secondary">Self-Signed</p><p>' + (a.self_signed ? 'Yes' : 'No') + '</p></div>' +
                '</div></div>';
        }

        /* Actions */
        html += '<div class="btn-group mb-4">' +
            '<button class="btn btn-primary" onclick="CertificatesPage.showUpload()">Upload Certificate</button>' +
            '<button class="btn" onclick="CertificatesPage.showGenerate()">Generate Self-Signed</button>' +
            '</div>';

        /* Store table */
        html += '<div class="card"><div class="card-header">' +
            '<h3>Certificate Store</h3></div>' +
            '<div id="certStoreTable"></div></div>';

        document.getElementById('certsContent').innerHTML = html;

        var store = data.store || [];
        Table.render('certStoreTable', [
            { key: 'filename', label: 'File' },
            { key: 'subject', label: 'Subject' },
            { key: 'key_type', label: 'Key Type' },
            { key: 'days_remaining', label: 'Expires', render: function(v) {
                if (v < 7) return '<span class="badge badge-red">' + v + ' days</span>';
                if (v < 30) return '<span class="badge badge-orange">' + v + ' days</span>';
                return '<span class="badge badge-green">' + v + ' days</span>';
            }},
            { key: 'self_signed', label: 'Type', render: function(v) {
                return v ? 'Self-Signed' : 'CA-Signed';
            }}
        ], store, [
            { label: 'Apply', handler: 'CertificatesPage.applyCert' },
            { label: 'Details', handler: 'CertificatesPage.viewDetails' }
        ]);

        /* Store for later reference */
        CertificatesPage._store = store;
    },

    showUpload: function() {
        Modal.show(
            '<h3>Upload Certificate</h3>' +
            '<div class="form-group"><label>Name</label>' +
            '<input type="text" id="uploadName" placeholder="my-cert"></div>' +
            '<div class="form-group"><label>Certificate PEM</label>' +
            '<textarea id="uploadCert" rows="6" placeholder="-----BEGIN CERTIFICATE-----"></textarea></div>' +
            '<div class="form-group"><label>Private Key PEM (optional)</label>' +
            '<textarea id="uploadKey" rows="6" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>' +
            '<div class="modal-footer">' +
            '<button class="btn" onclick="Modal.hide()">Cancel</button>' +
            '<button class="btn btn-primary" onclick="CertificatesPage.doUpload()">Upload</button></div>'
        );
    },

    doUpload: function() {
        var name = Form.getValue('uploadName');
        if (!name) { Toast.error('Name is required'); return; }

        API.uploadCert({
            name: name,
            cert_pem: Form.getValue('uploadCert'),
            key_pem: Form.getValue('uploadKey')
        }).then(function(r) {
            if (r.status === 'ok') {
                Modal.hide();
                Toast.success('Certificate uploaded');
                CertificatesPage.load();
            } else {
                Toast.error(r.error || 'Upload failed');
            }
        }).catch(function() { Toast.error('Upload failed'); });
    },

    showGenerate: function() {
        Modal.show(
            '<h3>Generate Self-Signed Certificate</h3>' +
            '<div class="form-group"><label>Common Name (CN)</label>' +
            '<input type="text" id="genCn" placeholder="localhost"></div>' +
            '<div class="grid grid-2">' +
            '<div class="form-group"><label>Organization</label>' +
            '<input type="text" id="genOrg" placeholder="My Company"></div>' +
            '<div class="form-group"><label>Country (2-letter)</label>' +
            '<input type="text" id="genCountry" placeholder="US" maxlength="2"></div>' +
            '</div>' +
            '<div class="grid grid-2">' +
            '<div class="form-group"><label>Key Type</label>' +
            '<select id="genKeyType">' +
            '<option value="rsa">RSA (2048-bit)</option>' +
            '<option value="ecdsa">ECDSA (P-256)</option></select></div>' +
            '<div class="form-group"><label>Validity (days)</label>' +
            '<input type="number" id="genDays" value="365"></div>' +
            '</div>' +
            '<div class="form-group"><label>Subject Alternative Names (comma-separated)</label>' +
            '<input type="text" id="genSans" placeholder="localhost,127.0.0.1"></div>' +
            '<div class="modal-footer">' +
            '<button class="btn" onclick="Modal.hide()">Cancel</button>' +
            '<button class="btn btn-primary" onclick="CertificatesPage.doGenerate()">Generate</button></div>'
        );
    },

    doGenerate: function() {
        var cn = Form.getValue('genCn');
        if (!cn) { Toast.error('Common Name is required'); return; }

        API.generateCert({
            cn: cn,
            org: Form.getValue('genOrg'),
            country: Form.getValue('genCountry'),
            key_type: Form.getValue('genKeyType'),
            days: Form.getInt('genDays') || 365,
            sans: Form.getValue('genSans')
        }).then(function(r) {
            if (r.status === 'ok') {
                Modal.hide();
                Toast.success('Certificate generated: ' + r.cert_file);
                CertificatesPage.load();
            } else {
                Toast.error(r.error || 'Generation failed');
            }
        }).catch(function() { Toast.error('Generation failed'); });
    },

    applyCert: function(idx) {
        var cert = CertificatesPage._store[idx];
        if (!cert) return;
        var name = cert.filename.replace(/\.(pem|crt)$/, '');
        Modal.confirm('Apply Certificate', 'Apply ' + cert.filename + ' as the server certificate and reload TLS?',
            function() {
                API.applyCert(name).then(function(r) {
                    if (r.status === 'ok') {
                        Toast.success('Certificate applied and TLS reloaded');
                        CertificatesPage.load();
                    } else {
                        Toast.error(r.error || 'Apply failed');
                    }
                }).catch(function() { Toast.error('Apply failed'); });
            }
        );
    },

    viewDetails: function(idx) {
        var cert = CertificatesPage._store[idx];
        if (!cert) return;

        Modal.show(
            '<h3>Certificate Details</h3>' +
            '<dl class="wizard-review">' +
            '<dt>File</dt><dd>' + escHtml(cert.filename) + '</dd>' +
            '<dt>Subject</dt><dd>' + escHtml(cert.subject) + '</dd>' +
            '<dt>Issuer</dt><dd>' + escHtml(cert.issuer) + '</dd>' +
            '<dt>Key Type</dt><dd>' + escHtml(cert.key_type) + '</dd>' +
            '<dt>Expires</dt><dd>' + escHtml(cert.not_after) + ' (' + cert.days_remaining + ' days)</dd>' +
            '<dt>Fingerprint</dt><dd style="font-family:monospace;font-size:0.85em;word-break:break-all">' +
            escHtml(cert.fingerprint || 'N/A') + '</dd>' +
            '<dt>Self-Signed</dt><dd>' + (cert.self_signed ? 'Yes' : 'No') + '</dd>' +
            '</dl>' +
            '<div class="modal-footer"><button class="btn" onclick="Modal.hide()">Close</button></div>'
        );
    },

    destroy: function() {}
};
