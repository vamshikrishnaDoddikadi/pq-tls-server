/**
 * TLS / SSL configuration page — Crypto Agility Panel
 */
var TlsPage = {
    _active: [],    /* ordered tls_group strings currently enabled */
    _meta: {},      /* tls_group -> { name, tls_group, nist_level, family, status } */
    _dragIdx: -1,

    render: function() {
        return '<h2 class="page-title">TLS / SSL</h2>' +
            '<div id="tlsContent"><div class="loading">Loading...</div></div>';
    },

    init: function() {
        Promise.all([API.getConfig(), API.getAlgorithms()])
            .then(function(results) {
                TlsPage._buildMeta(results[1]);
                TlsPage.renderContent(results[0]);
            })
            .catch(function() {
                /* Fallback if algorithms endpoint unavailable */
                API.getConfig().then(function(cfg) {
                    TlsPage._meta = {};
                    TlsPage.renderContent(cfg);
                }).catch(function() {
                    Toast.error('Failed to load TLS config');
                });
            });
    },

    _buildMeta: function(algos) {
        TlsPage._meta = {};
        if (!algos) return;

        /* Hybrid KEMs from registry */
        (algos.hybrid_kems || []).forEach(function(h) {
            if (!h.tls_group) return;
            TlsPage._meta[h.tls_group] = {
                name: h.label || h.tls_group,
                tls_group: h.tls_group,
                nist_level: h.nist_level || 0,
                family: 'Hybrid',
                status: 0
            };
        });

        /* Classical KEM providers (available only, family=4) */
        (algos.kem_providers || []).forEach(function(k) {
            if (k.family !== 4 || !k.available) return;
            if (TlsPage._meta[k.name]) return;
            TlsPage._meta[k.name] = {
                name: k.name,
                tls_group: k.name,
                nist_level: k.nist_level || 0,
                family: 'Classical',
                status: k.status || 0
            };
        });
    },

    renderContent: function(cfg) {
        var tls = cfg.tls || {};
        var hasMeta = Object.keys(TlsPage._meta).length > 0;

        /* Parse current groups into active list */
        TlsPage._active = (tls.groups || '').split(':').filter(Boolean);

        var html = '';

        /* ---- Certificate card (unchanged) ---- */
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

        /* ---- Crypto Agility Panel ---- */
        html += '<div class="card mb-4">' +
            '<h3>Key Exchange Groups <span class="badge badge-orange">Requires Restart</span></h3>';

        if (hasMeta) {
            html += '<div class="algo-list-header">Active Groups ' +
                '<span class="text-secondary">\u2014 drag to reorder</span></div>' +
                '<div class="algo-list" id="algoActive"' +
                ' ondragover="TlsPage._onDragOver(event)"' +
                ' ondrop="TlsPage._onDrop(event)"></div>' +
                '<div class="algo-list-header mt-4">Available</div>' +
                '<div class="algo-list" id="algoAvailable"></div>' +
                '<div class="algo-preview-wrap">' +
                '<label>Preview</label>' +
                '<div class="algo-preview" id="algoPreview"></div>' +
                '</div>' +
                '<div class="btn-group mt-4">' +
                '<button class="btn btn-primary" onclick="TlsPage.saveGroups()">Save Groups</button>' +
                '</div>';
        } else {
            /* Fallback: plain text input if /api/algorithms unavailable */
            html += '<div class="form-group"><label>Groups</label>' +
                '<input type="text" id="tlsGroups" value="' + escHtml(tls.groups || '') + '">' +
                '<p class="text-muted mt-2">Colon-separated. e.g. X25519MLKEM768:X25519</p></div>' +
                '<div class="btn-group mt-4">' +
                '<button class="btn btn-primary" onclick="TlsPage.saveGroups()">Save Groups</button>' +
                '</div>';
        }
        html += '</div>';

        /* ---- Protocol Settings ---- */
        html += '<div class="card mb-4">' +
            '<h3>Protocol Settings</h3>' +
            '<div class="form-group"><label>Minimum TLS Version</label>' +
            '<select id="tlsMinVer">' +
            '<option value="1.3"' + (tls.min_version === '1.3' ? ' selected' : '') + '>TLS 1.3</option>' +
            '<option value="1.2"' + (tls.min_version === '1.2' ? ' selected' : '') + '>TLS 1.2</option>' +
            '</select></div>' +
            '<div class="form-group"><label>Session Cache Size</label>' +
            '<input type="number" id="tlsSessionCache" value="' + (tls.session_cache_size || 0) + '">' +
            '</div>' +
            '<div class="btn-group">' +
            '<button class="btn btn-primary" onclick="TlsPage.save()">Save Changes</button>' +
            '</div></div>';

        document.getElementById('tlsContent').innerHTML = html;

        if (hasMeta) TlsPage._updateAlgoUI();
    },

    /* ---- Badge helpers ---- */

    _levelBadge: function(level) {
        var cls = level >= 5 ? 'l5' : level >= 3 ? 'l3' : 'l1';
        return '<span class="algo-badge algo-badge-' + cls + '">L' + level + '</span>';
    },

    _familyBadge: function(family) {
        var cls = family === 'Hybrid' ? 'hybrid' :
                  family === 'Classical' ? 'classical' : 'pq';
        return '<span class="algo-badge algo-badge-' + cls + '">' + escHtml(family) + '</span>';
    },

    _statusBadge: function(status) {
        var map = [
            ['Standard',     'standard'],
            ['Candidate',    'candidate'],
            ['Draft',        'candidate'],
            ['Experimental', 'experimental'],
            ['Deprecated',   'deprecated']
        ];
        var entry = map[status] || map[0];
        return '<span class="algo-badge algo-badge-' + entry[1] + '">' + entry[0] + '</span>';
    },

    /* ---- Card rendering ---- */

    _renderActiveCard: function(group, idx) {
        var m = TlsPage._meta[group] || {
            name: group, nist_level: 0, family: 'Unknown', status: 0
        };
        return '<div class="algo-card" draggable="true" data-idx="' + idx + '"' +
            ' data-group="' + escHtml(group) + '"' +
            ' ondragstart="TlsPage._onDragStart(event)"' +
            ' ondragend="TlsPage._onDragEnd(event)">' +
            '<span class="drag-handle">\u283f</span>' +
            '<span class="algo-priority-num">' + (idx + 1) + '</span>' +
            '<span class="algo-card-name">' + escHtml(m.name) + '</span>' +
            '<span class="algo-card-badges">' +
            TlsPage._levelBadge(m.nist_level) +
            TlsPage._familyBadge(m.family) +
            TlsPage._statusBadge(m.status) +
            '</span>' +
            '<span class="algo-card-action" onclick="TlsPage.removeAlgo(\'' +
            escHtml(group) + '\')" title="Remove">\u00d7</span>' +
            '</div>';
    },

    _renderAvailableCard: function(group) {
        var m = TlsPage._meta[group];
        return '<div class="algo-card disabled" data-group="' + escHtml(group) + '">' +
            '<span class="algo-card-action add" onclick="TlsPage.addAlgo(\'' +
            escHtml(group) + '\')" title="Add">+</span>' +
            '<span class="algo-card-name">' + escHtml(m.name) + '</span>' +
            '<span class="algo-card-badges">' +
            TlsPage._levelBadge(m.nist_level) +
            TlsPage._familyBadge(m.family) +
            TlsPage._statusBadge(m.status) +
            '</span>' +
            '</div>';
    },

    _updateAlgoUI: function() {
        /* Active cards */
        var activeHtml = '';
        TlsPage._active.forEach(function(g, i) {
            activeHtml += TlsPage._renderActiveCard(g, i);
        });
        if (!activeHtml) {
            activeHtml = '<div class="text-muted" style="padding:16px;font-size:0.8em;' +
                'text-align:center">No active groups \u2014 click + to add from available</div>';
        }
        var el = document.getElementById('algoActive');
        if (el) el.innerHTML = activeHtml;

        /* Available cards (everything in meta not currently active) */
        var activeSet = {};
        TlsPage._active.forEach(function(g) { activeSet[g] = true; });
        var availHtml = '';
        Object.keys(TlsPage._meta).forEach(function(g) {
            if (!activeSet[g]) availHtml += TlsPage._renderAvailableCard(g);
        });
        if (!availHtml) {
            availHtml = '<div class="text-muted" style="padding:16px;font-size:0.8em;' +
                'text-align:center">All algorithms are active</div>';
        }
        el = document.getElementById('algoAvailable');
        if (el) el.innerHTML = availHtml;

        /* Preview string */
        el = document.getElementById('algoPreview');
        if (el) el.textContent = TlsPage._active.join(':') || '(none)';
    },

    /* ---- Add / Remove ---- */

    addAlgo: function(group) {
        if (TlsPage._active.indexOf(group) < 0) {
            TlsPage._active.push(group);
            TlsPage._updateAlgoUI();
        }
    },

    removeAlgo: function(group) {
        var idx = TlsPage._active.indexOf(group);
        if (idx >= 0) {
            TlsPage._active.splice(idx, 1);
            TlsPage._updateAlgoUI();
        }
    },

    /* ---- Drag & Drop (HTML5) ---- */

    _onDragStart: function(e) {
        var card = e.target.closest('.algo-card');
        if (!card) return;
        TlsPage._dragIdx = parseInt(card.dataset.idx, 10);
        card.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', card.dataset.idx);
    },

    _onDragOver: function(e) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        /* Highlight drop target */
        document.querySelectorAll('.algo-card.drag-over').forEach(function(c) {
            c.classList.remove('drag-over');
        });
        var card = e.target.closest('.algo-card');
        if (card && card.dataset.idx !== undefined) {
            card.classList.add('drag-over');
        }
    },

    _onDrop: function(e) {
        e.preventDefault();
        document.querySelectorAll('.algo-card.drag-over').forEach(function(c) {
            c.classList.remove('drag-over');
        });
        if (TlsPage._dragIdx < 0) return;

        var card = e.target.closest('.algo-card');
        var dropIdx = card && card.dataset.idx !== undefined
            ? parseInt(card.dataset.idx, 10)
            : TlsPage._active.length - 1;
        var dragIdx = TlsPage._dragIdx;

        if (dragIdx !== dropIdx) {
            var item = TlsPage._active.splice(dragIdx, 1)[0];
            if (dragIdx < dropIdx) dropIdx--;
            TlsPage._active.splice(dropIdx, 0, item);
        }
        TlsPage._dragIdx = -1;
        TlsPage._updateAlgoUI();
    },

    _onDragEnd: function(e) {
        TlsPage._dragIdx = -1;
        document.querySelectorAll('.algo-card.dragging').forEach(function(c) {
            c.classList.remove('dragging');
        });
    },

    /* ---- Save ---- */

    saveGroups: function() {
        var groups = Object.keys(TlsPage._meta).length > 0
            ? TlsPage._active.join(':')
            : Form.getValue('tlsGroups');
        API.putTls({ groups: groups }).then(function(r) {
            if (r.restart_required) {
                Toast.warning('Groups saved. Restart required to apply.');
                PQ.showRestartBanner();
            } else {
                Toast.success('Key exchange groups saved');
            }
        }).catch(function() { Toast.error('Failed to save groups'); });
    },

    save: function() {
        API.putTls({
            cert: Form.getValue('tlsCert'),
            key: Form.getValue('tlsKey'),
            ca: Form.getValue('tlsCa'),
            client_auth: Form.getValue('tlsClientAuth'),
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
