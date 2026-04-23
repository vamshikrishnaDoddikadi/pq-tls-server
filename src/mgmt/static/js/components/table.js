/**
 * Sortable table helper
 */
var Table = {
    render: function(containerId, columns, rows, actions) {
        var html = '<div class="table-wrap"><table><thead><tr>';
        columns.forEach(function(col) {
            html += '<th>' + col.label + '</th>';
        });
        if (actions) html += '<th>Actions</th>';
        html += '</tr></thead><tbody>';

        if (rows.length === 0) {
            html += '<tr><td colspan="' + (columns.length + (actions ? 1 : 0)) +
                    '" style="text-align:center;color:var(--text-muted);padding:24px">' +
                    'No entries</td></tr>';
        }

        rows.forEach(function(row, idx) {
            html += '<tr>';
            columns.forEach(function(col) {
                var val = row[col.key];
                if (col.render) val = col.render(val, row, idx);
                html += '<td>' + (val != null ? val : '') + '</td>';
            });
            if (actions) {
                html += '<td class="btn-group">';
                actions.forEach(function(act) {
                    html += '<button class="btn btn-sm" onclick="' +
                            act.handler + '(' + idx + ')">' + act.label + '</button>';
                });
                html += '</td>';
            }
            html += '</tr>';
        });

        html += '</tbody></table></div>';
        document.getElementById(containerId).innerHTML = html;
    }
};
