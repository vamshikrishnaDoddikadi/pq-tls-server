/**
 * Reusable modal dialog component
 */
var Modal = {
    show: function(html) {
        document.getElementById('modalContent').innerHTML = html;
        document.getElementById('modalOverlay').style.display = 'flex';
    },

    hide: function() {
        document.getElementById('modalOverlay').style.display = 'none';
        document.getElementById('modalContent').innerHTML = '';
    },

    confirm: function(title, message, onConfirm) {
        this.show(
            '<h3>' + title + '</h3>' +
            '<p style="color:var(--text-secondary);margin-bottom:16px">' + message + '</p>' +
            '<div class="modal-footer">' +
            '<button class="btn" onclick="Modal.hide()">Cancel</button>' +
            '<button class="btn btn-danger" id="modalConfirmBtn">Confirm</button>' +
            '</div>'
        );
        document.getElementById('modalConfirmBtn').onclick = function() {
            Modal.hide();
            if (onConfirm) onConfirm();
        };
    }
};

/* Close modal on overlay click */
document.getElementById('modalOverlay').addEventListener('click', function(e) {
    if (e.target === this) Modal.hide();
});

/* Close modal on Escape key */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') Modal.hide();
});
