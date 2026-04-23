/**
 * PQ-TLS Management — SPA Router & App Controller
 */
window.escHtml = function(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
};

var PQ = (function() {
    var currentPage = null;
    var pages = {
        dashboard: DashboardPage,
        tls: TlsPage,
        upstreams: UpstreamsPage,
        security: SecurityPage,
        settings: SettingsPage,
        certificates: CertificatesPage,
        logs: LogsPage
    };

    function getRoute() {
        var hash = window.location.hash || '#/dashboard';
        return hash.replace('#/', '').split('?')[0];
    }

    function navigate(route) {
        /* Destroy previous page */
        if (currentPage && currentPage.destroy) {
            currentPage.destroy();
        }

        var page = pages[route];
        if (!page) {
            route = 'dashboard';
            page = pages[route];
        }

        /* Update nav */
        document.querySelectorAll('.nav-link').forEach(function(el) {
            el.classList.toggle('active', el.getAttribute('data-page') === route);
        });

        /* Render page */
        var content = document.getElementById('pageContent');
        content.innerHTML = page.render();

        currentPage = page;

        /* Init after render */
        if (page.init) {
            page.init();
        }
    }

    function showApp() {
        document.getElementById('loginOverlay').style.display = 'none';
        document.getElementById('setupOverlay').style.display = 'none';
        document.getElementById('appLayout').style.display = 'flex';
        navigate(getRoute());
        checkRestartPending();
    }

    function checkRestartPending() {
        API.getConfig().then(function(cfg) {
            if (cfg.restart_pending) {
                document.getElementById('restartBanner').style.display = 'flex';
            }
        }).catch(function() {});
    }

    /* Hash-based routing */
    window.addEventListener('hashchange', function() {
        if (document.getElementById('appLayout').style.display !== 'none') {
            navigate(getRoute());
        }
    });

    /* Logout handler */
    document.getElementById('logoutBtn').addEventListener('click', function(e) {
        e.preventDefault();
        API.logout().then(function() {
            API.clearToken();
            if (currentPage && currentPage.destroy) currentPage.destroy();
            LoginPage.show();
            Toast.info('Logged out');
        }).catch(function() {
            API.clearToken();
            if (currentPage && currentPage.destroy) currentPage.destroy();
            LoginPage.show();
        });
    });

    return {
        init: function() {
            showApp();
        },

        showLogin: function() {
            LoginPage.show();
        },

        showRestartBanner: function() {
            document.getElementById('restartBanner').style.display = 'flex';
        },

        restartServer: function() {
            Modal.confirm('Restart Server',
                'This will restart the PQ-TLS server. Active connections will be drained. Continue?',
                function() {
                    API.restart().then(function() {
                        Toast.info('Server is restarting...');
                        document.getElementById('restartBanner').style.display = 'none';
                        /* Wait and try to reconnect */
                        setTimeout(function() {
                            window.location.reload();
                        }, 3000);
                    }).catch(function() {
                        Toast.error('Restart request failed');
                    });
                }
            );
        }
    };
})();

/* Boot */
(function() {
    /* Check if we have a stored token */
    if (API.getToken()) {
        API.authStatus().then(function(data) {
            if (data.authenticated) {
                PQ.init();
            } else if (data.needs_setup) {
                SetupPage.show();
            } else {
                API.clearToken();
                LoginPage.show();
            }
        }).catch(function() {
            LoginPage.show();
        });
    } else {
        /* Check if setup needed */
        API.authStatus().then(function(data) {
            if (data.needs_setup) {
                SetupPage.show();
            } else {
                LoginPage.show();
            }
        }).catch(function() {
            LoginPage.show();
        });
    }
})();
