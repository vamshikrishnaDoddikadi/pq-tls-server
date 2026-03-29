/**
 * Toast notification component
 */
var Toast = {
    show: function(message, type, duration) {
        type = type || 'info';
        duration = duration || 3000;

        var container = document.getElementById('toastContainer');
        var el = document.createElement('div');
        el.className = 'toast toast-' + type;
        el.textContent = message;
        container.appendChild(el);

        setTimeout(function() {
            el.style.opacity = '0';
            el.style.transform = 'translateX(100%)';
            el.style.transition = 'all 0.3s';
            setTimeout(function() { el.remove(); }, 300);
        }, duration);
    },
    success: function(msg) { this.show(msg, 'success'); },
    error: function(msg) { this.show(msg, 'error', 5000); },
    info: function(msg) { this.show(msg, 'info'); },
    warning: function(msg) { this.show(msg, 'warning'); }
};
