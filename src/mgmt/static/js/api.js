/**
 * API client — fetch wrappers for all management endpoints
 */
var API = (function() {
    var token = localStorage.getItem('mgmt_token') || '';

    function headers(extra) {
        var h = { 'Content-Type': 'application/json' };
        if (token) h['Authorization'] = 'Bearer ' + token;
        if (extra) Object.assign(h, extra);
        return h;
    }

    function request(method, path, body) {
        var opts = { method: method, headers: headers() };
        if (body) opts.body = JSON.stringify(body);
        return fetch(path, opts).then(function(r) {
            if (r.status === 401) {
                token = '';
                localStorage.removeItem('mgmt_token');
                PQ.showLogin();
                return Promise.reject(new Error('Unauthorized'));
            }
            return r.json().catch(function() { return { error: 'Invalid response' }; });
        });
    }

    return {
        setToken: function(t) {
            token = t;
            localStorage.setItem('mgmt_token', t);
        },

        clearToken: function() {
            token = '';
            localStorage.removeItem('mgmt_token');
        },

        getToken: function() { return token; },

        /* Auth */
        login: function(user, pass) {
            return request('POST', '/api/auth/login', { username: user, password: pass });
        },
        logout: function() {
            return request('POST', '/api/auth/logout');
        },
        authStatus: function() {
            return request('GET', '/api/auth/status');
        },
        setup: function(user, pass) {
            return request('POST', '/api/auth/setup', { username: user, password: pass });
        },

        /* Monitoring (no auth) */
        stats: function() {
            return fetch('/api/stats').then(function(r) { return r.json(); });
        },

        /* Config */
        getConfig: function() {
            return request('GET', '/api/config');
        },
        putListen: function(data) {
            return request('PUT', '/api/config/listen', data);
        },
        putTls: function(data) {
            return request('PUT', '/api/config/tls', data);
        },
        reloadTls: function() {
            return request('POST', '/api/config/tls/reload');
        },
        putUpstreams: function(data) {
            return request('PUT', '/api/config/upstreams', data);
        },
        putServer: function(data) {
            return request('PUT', '/api/config/server', data);
        },
        putLogging: function(data) {
            return request('PUT', '/api/config/logging', data);
        },
        putRateLimit: function(data) {
            return request('PUT', '/api/config/rate_limit', data);
        },
        putAcl: function(data) {
            return request('PUT', '/api/config/acl', data);
        },

        /* Certificates */
        listCerts: function() {
            return request('GET', '/api/certs');
        },
        uploadCert: function(data) {
            return request('POST', '/api/certs/upload', data);
        },
        generateCert: function(data) {
            return request('POST', '/api/certs/generate', data);
        },
        applyCert: function(name) {
            return request('POST', '/api/certs/' + encodeURIComponent(name) + '/apply');
        },
        certDetails: function(name) {
            return request('GET', '/api/certs/' + encodeURIComponent(name) + '/details');
        },

        /* Management */
        mgmtStatus: function() {
            return request('GET', '/api/mgmt/status');
        },
        restart: function() {
            return request('POST', '/api/mgmt/restart', { confirm: true });
        },

        /* Logs */
        logsRecent: function(lines) {
            return request('GET', '/api/logs/recent?lines=' + (lines || 100));
        },

        /* Algorithms (public — no auth) */
        getAlgorithms: function() {
            return fetch('/api/algorithms').then(function(r) { return r.json(); });
        }
    };
})();
