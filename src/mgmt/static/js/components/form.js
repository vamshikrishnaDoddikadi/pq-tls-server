/**
 * Form validation helpers
 */
var Form = {
    getValue: function(id) {
        var el = document.getElementById(id);
        if (!el) return '';
        if (el.type === 'checkbox') return el.checked;
        return el.value;
    },

    getInt: function(id) {
        return parseInt(Form.getValue(id), 10) || 0;
    },

    setValue: function(id, val) {
        var el = document.getElementById(id);
        if (!el) return;
        if (el.type === 'checkbox') el.checked = !!val;
        else el.value = val != null ? val : '';
    },

    validateRequired: function(id, label) {
        var val = Form.getValue(id);
        if (!val || (typeof val === 'string' && val.trim() === '')) {
            Toast.error(label + ' is required');
            document.getElementById(id).focus();
            return false;
        }
        return true;
    },

    validatePort: function(id) {
        var val = Form.getInt(id);
        if (val < 1 || val > 65535) {
            Toast.error('Port must be between 1 and 65535');
            document.getElementById(id).focus();
            return false;
        }
        return true;
    },

    validateCidr: function(value) {
        var parts = value.split('/');
        var ip = parts[0];
        var prefix = parts.length > 1 ? parseInt(parts[1], 10) : 32;

        var ipParts = ip.split('.');
        if (ipParts.length !== 4) return false;
        for (var i = 0; i < 4; i++) {
            var n = parseInt(ipParts[i], 10);
            if (isNaN(n) || n < 0 || n > 255) return false;
        }
        if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;
        return true;
    },

    passwordStrength: function(password) {
        var score = 0;
        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[^a-zA-Z\d]/.test(password)) score++;

        if (score <= 2) return 'weak';
        if (score <= 3) return 'medium';
        return 'strong';
    }
};
