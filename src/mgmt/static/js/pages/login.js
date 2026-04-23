/**
 * Login page
 */
var LoginPage = {
    render: function() {
        return '<div class="login-card">' +
            '<h2>PQ-TLS Server</h2>' +
            '<p class="subtitle">Management Dashboard</p>' +
            '<div class="login-error" id="loginError"></div>' +
            '<div class="form-group">' +
            '<label>Username</label>' +
            '<input type="text" id="loginUser" placeholder="admin" autocomplete="username">' +
            '</div>' +
            '<div class="form-group">' +
            '<label>Password</label>' +
            '<input type="password" id="loginPass" placeholder="Password" autocomplete="current-password">' +
            '</div>' +
            '<button class="btn btn-primary" style="width:100%;justify-content:center;margin-top:8px" onclick="LoginPage.submit()">Sign In</button>' +
            '</div>';
    },

    show: function() {
        document.getElementById('loginContainer').innerHTML = this.render();
        document.getElementById('loginOverlay').style.display = 'flex';
        document.getElementById('appLayout').style.display = 'none';

        /* Enter key submits */
        var passEl = document.getElementById('loginPass');
        if (passEl) {
            passEl.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') LoginPage.submit();
            });
        }
    },

    hide: function() {
        document.getElementById('loginOverlay').style.display = 'none';
        document.getElementById('appLayout').style.display = 'flex';
    },

    submit: function() {
        var user = Form.getValue('loginUser');
        var pass = Form.getValue('loginPass');
        var errEl = document.getElementById('loginError');

        if (!user || !pass) {
            errEl.textContent = 'Please enter username and password';
            errEl.style.display = 'block';
            return;
        }

        API.login(user, pass).then(function(data) {
            if (data.token) {
                API.setToken(data.token);
                LoginPage.hide();
                PQ.init();
                Toast.success('Logged in successfully');
            } else {
                errEl.textContent = data.error || 'Invalid credentials';
                errEl.style.display = 'block';
            }
        }).catch(function() {
            errEl.textContent = 'Connection error';
            errEl.style.display = 'block';
        });
    }
};
