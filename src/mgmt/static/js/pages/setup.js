/**
 * First-run setup wizard
 */
var SetupPage = {
    step: 1,
    maxSteps: 4,
    data: {},

    show: function() {
        document.getElementById('setupOverlay').style.display = 'flex';
        document.getElementById('loginOverlay').style.display = 'none';
        document.getElementById('appLayout').style.display = 'none';
        this.step = 1;
        this.renderStep();
    },

    hide: function() {
        document.getElementById('setupOverlay').style.display = 'none';
    },

    renderStep: function() {
        var steps = '';
        for (var i = 1; i <= this.maxSteps; i++) {
            var cls = i < this.step ? 'done' : (i === this.step ? 'active' : '');
            steps += '<div class="wizard-step ' + cls + '"></div>';
        }

        var body = '';
        switch (this.step) {
        case 1:
            body = '<div class="wizard-welcome">' +
                '<h3 style="font-size:1.3em;margin-bottom:16px">Welcome</h3>' +
                '<p>This wizard will help you configure your PQ-TLS server ' +
                'management dashboard.</p>' +
                '<p>You\'ll create an admin account and optionally configure ' +
                'basic server settings.</p></div>';
            break;
        case 2:
            body = '<h3 style="font-size:1.1em;margin-bottom:16px">Create Admin Account</h3>' +
                '<div class="form-group">' +
                '<label>Username</label>' +
                '<input type="text" id="setupUser" value="' + (this.data.username || 'admin') + '">' +
                '</div>' +
                '<div class="form-group">' +
                '<label>Password</label>' +
                '<input type="password" id="setupPass" oninput="SetupPage.checkStrength()">' +
                '<div class="password-strength" id="passStrength"></div>' +
                '</div>' +
                '<div class="form-group">' +
                '<label>Confirm Password</label>' +
                '<input type="password" id="setupPassConfirm">' +
                '</div>';
            break;
        case 3:
            body = '<h3 style="font-size:1.1em;margin-bottom:16px">Basic Configuration</h3>' +
                '<div class="form-group">' +
                '<label>TLS Certificate Path</label>' +
                '<input type="text" id="setupCert" value="' + (this.data.cert || 'certs/server-cert.pem') + '">' +
                '</div>' +
                '<div class="form-group">' +
                '<label>TLS Key Path</label>' +
                '<input type="text" id="setupKey" value="' + (this.data.key || 'certs/server-key.pem') + '">' +
                '</div>' +
                '<div class="form-group">' +
                '<label>Upstream Backend (host:port)</label>' +
                '<input type="text" id="setupBackend" value="' + (this.data.backend || '127.0.0.1:8080') + '">' +
                '</div>' +
                '<p class="text-muted mt-2">These can be changed later from the dashboard.</p>';
            break;
        case 4:
            body = '<h3 style="font-size:1.1em;margin-bottom:16px">Review</h3>' +
                '<dl class="wizard-review">' +
                '<dt>Admin Username</dt><dd>' + escHtml(this.data.username || '') + '</dd>' +
                '<dt>Certificate</dt><dd>' + (this.data.cert || 'default') + '</dd>' +
                '<dt>Key</dt><dd>' + (this.data.key || 'default') + '</dd>' +
                '<dt>Backend</dt><dd>' + (this.data.backend || 'default') + '</dd>' +
                '</dl>';
            break;
        }

        var prevBtn = this.step > 1
            ? '<button class="btn" onclick="SetupPage.prev()">Back</button>'
            : '<div></div>';
        var nextBtn = this.step < this.maxSteps
            ? '<button class="btn btn-primary" onclick="SetupPage.next()">Next</button>'
            : '<button class="btn btn-success" onclick="SetupPage.finish()">Complete Setup</button>';

        document.getElementById('setupContainer').innerHTML =
            '<div class="wizard-card">' +
            '<h2>PQ-TLS Server</h2>' +
            '<p class="wizard-subtitle">Initial Setup</p>' +
            '<div class="wizard-steps">' + steps + '</div>' +
            '<div class="wizard-body">' + body + '</div>' +
            '<div class="wizard-footer">' + prevBtn + nextBtn + '</div>' +
            '</div>';
    },

    checkStrength: function() {
        var pass = Form.getValue('setupPass');
        var el = document.getElementById('passStrength');
        if (!pass) { el.className = 'password-strength'; return; }
        el.className = 'password-strength ' + Form.passwordStrength(pass);
    },

    next: function() {
        if (this.step === 2) {
            var user = Form.getValue('setupUser');
            var pass = Form.getValue('setupPass');
            var confirm = Form.getValue('setupPassConfirm');

            if (!user || user.length < 3) {
                Toast.error('Username must be at least 3 characters');
                return;
            }
            if (!pass || pass.length < 8) {
                Toast.error('Password must be at least 8 characters');
                return;
            }
            if (pass !== confirm) {
                Toast.error('Passwords do not match');
                return;
            }

            this.data.username = user;
            this.data.password = pass;
        }
        if (this.step === 3) {
            this.data.cert = Form.getValue('setupCert');
            this.data.key = Form.getValue('setupKey');
            this.data.backend = Form.getValue('setupBackend');
        }

        this.step++;
        this.renderStep();
    },

    prev: function() {
        if (this.step > 1) {
            this.step--;
            this.renderStep();
        }
    },

    finish: function() {
        API.setup(this.data.username, this.data.password).then(function(data) {
            if (data.token) {
                API.setToken(data.token);
                SetupPage.data = {};
                SetupPage.hide();
                Toast.success('Setup complete! Welcome to PQ-TLS Management.');
                PQ.init();
            } else {
                Toast.error(data.error || 'Setup failed');
            }
        }).catch(function() {
            Toast.error('Connection error during setup');
        });
    }
};
