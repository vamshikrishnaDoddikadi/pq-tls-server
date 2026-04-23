/**
 * Security page — Rate limiting + ACL
 */
var SecurityPage = {
    config: null,
    aclEntries: [],

    render: function() {
        return '<h2 class="page-title">Security</h2>' +
        '<div id="securityContent"><div class="loading">Loading...</div></div>';
    },

    init: function() {
        API.getConfig().then(function(cfg) {
            SecurityPage.config = cfg;
            SecurityPage.aclEntries = (cfg.acl && cfg.acl.entries) || [];
            SecurityPage.renderContent(cfg);
        }).catch(function() { Toast.error('Failed to load security config'); });
    },

    renderContent: function(cfg) {
        var rl = cfg.rate_limit || {};
        var acl = cfg.acl || {};
        var html = '';

        /* Rate Limiting */
        html += '<div class="card mb-4">' +
            '<div class="card-header"><h3>Rate Limiting</h3>' +
            '<span class="badge badge-green">Applied Instantly</span></div>' +
            '<div class="grid grid-2">' +
            '<div class="form-group"><label>Per-IP Connections/sec (0=disabled)</label>' +
            '<input type="number" id="rlPerIp" value="' + (rl.per_ip || 0) + '"></div>' +
            '<div class="form-group"><label>Burst Capacity</label>' +
            '<input type="number" id="rlBurst" value="' + (rl.burst || 0) + '"></div>' +
            '</div>' +
            '<button class="btn btn-success" onclick="SecurityPage.saveRateLimit()">Apply Rate Limit</button>' +
            '</div>';

        /* ACL */
        html += '<div class="card mb-4">' +
            '<div class="card-header"><h3>Access Control List</h3>' +
            '<span class="badge badge-green">Applied Instantly</span></div>' +
            '<div class="form-group"><label>ACL Mode</label>' +
            '<select id="aclMode">' +
            '<option value="disabled"' + (acl.mode === 'disabled' ? ' selected' : '') + '>Disabled</option>' +
            '<option value="allowlist"' + (acl.mode === 'allowlist' ? ' selected' : '') + '>Allowlist</option>' +
            '<option value="blocklist"' + (acl.mode === 'blocklist' ? ' selected' : '') + '>Blocklist</option>' +
            '</select></div>' +
            '<div id="aclTable"></div>' +
            '<div class="inline-flex mt-4">' +
            '<input type="text" id="aclNewEntry" placeholder="192.168.1.0/24" style="width:250px">' +
            '<button class="btn btn-sm" onclick="SecurityPage.addAclEntry()">Add Entry</button>' +
            '</div>' +
            '<div class="mt-4">' +
            '<button class="btn btn-success" onclick="SecurityPage.saveAcl()">Apply ACL</button>' +
            '</div></div>';

        document.getElementById('securityContent').innerHTML = html;
        this.renderAclTable();
    },

    renderAclTable: function() {
        Table.render('aclTable', [
            { key: 'entry', label: 'IP / CIDR' }
        ], this.aclEntries.map(function(e) { return { entry: e }; }), [
            { label: 'Remove', handler: 'SecurityPage.removeAclEntry' }
        ]);
    },

    addAclEntry: function() {
        var entry = Form.getValue('aclNewEntry').trim();
        if (!entry) { Toast.error('Enter an IP or CIDR range'); return; }
        if (!Form.validateCidr(entry)) { Toast.error('Invalid CIDR format'); return; }

        this.aclEntries.push(entry);
        Form.setValue('aclNewEntry', '');
        this.renderAclTable();
    },

    removeAclEntry: function(idx) {
        SecurityPage.aclEntries.splice(idx, 1);
        SecurityPage.renderAclTable();
    },

    saveRateLimit: function() {
        API.putRateLimit({
            per_ip: Form.getInt('rlPerIp'),
            burst: Form.getInt('rlBurst')
        }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Saved. Restart required.');
                PQ.showRestartBanner();
            } else {
                Toast.success('Rate limit applied');
            }
        }).catch(function() { Toast.error('Failed to apply rate limit'); });
    },

    saveAcl: function() {
        API.putAcl({
            mode: Form.getValue('aclMode'),
            entries: this.aclEntries
        }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Saved. Restart required.');
                PQ.showRestartBanner();
            } else {
                Toast.success('ACL applied');
            }
        }).catch(function() { Toast.error('Failed to apply ACL'); });
    },

    destroy: function() {}
};
