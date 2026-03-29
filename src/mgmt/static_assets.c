/**
 * @file static_assets.c
 * @brief Embedded frontend assets — placeholder until tools/embed_assets.sh is run
 *
 * This file provides a minimal fallback HTML dashboard.
 * Run `bash tools/embed_assets.sh` to embed the full SPA frontend.
 */

#include "static_assets.h"
#include <string.h>

/* Minimal fallback index.html */
static const unsigned char asset_index_html[] =
"<!DOCTYPE html>\n"
"<html lang=\"en\"><head><meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>PQ-TLS Server Management</title>\n"
"<style>\n"
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
"background:#0d1117;color:#e6edf3;display:flex;align-items:center;"
"justify-content:center;min-height:100vh}\n"
".card{background:#161b22;border:1px solid #30363d;border-radius:12px;"
"padding:40px;max-width:480px;text-align:center}\n"
"h1{background:linear-gradient(90deg,#58a6ff,#bc8cff);"
"-webkit-background-clip:text;-webkit-text-fill-color:transparent;"
"margin-bottom:12px}\n"
".sub{color:#8b949e;margin-bottom:24px}\n"
"input{width:100%;padding:10px;margin:6px 0;background:#0d1117;"
"border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px}\n"
"input:focus{outline:none;border-color:#58a6ff}\n"
"button{width:100%;padding:10px;margin-top:12px;background:#58a6ff;"
"border:none;border-radius:6px;color:#fff;font-size:14px;cursor:pointer;"
"font-weight:600}\n"
"button:hover{background:#4c99eb}\n"
".error{color:#f85149;font-size:13px;margin-top:8px;display:none}\n"
".info{color:#8b949e;font-size:12px;margin-top:20px}\n"
"</style></head><body>\n"
"<div class=\"card\">\n"
"<h1>PQ-TLS Server</h1>\n"
"<p class=\"sub\">Management Dashboard</p>\n"
"<div id=\"loginForm\">\n"
"<input type=\"text\" id=\"user\" placeholder=\"Username\">\n"
"<input type=\"password\" id=\"pass\" placeholder=\"Password\">\n"
"<button onclick=\"doLogin()\">Sign In</button>\n"
"<p class=\"error\" id=\"err\"></p>\n"
"</div>\n"
"<p class=\"info\">Run <code>bash tools/embed_assets.sh</code> then rebuild "
"to enable the full management UI.</p>\n"
"</div>\n"
"<script>\n"
"function doLogin(){\n"
"  var u=document.getElementById('user').value;\n"
"  var p=document.getElementById('pass').value;\n"
"  fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({username:u,password:p})}).then(r=>r.json()).then(d=>{\n"
"    if(d.token){localStorage.setItem('mgmt_token',d.token);"
"document.getElementById('loginForm').innerHTML="
"'<p style=\"color:#3fb950\">Logged in. Full UI requires embed step.</p>';}\n"
"    else{var e=document.getElementById('err');e.textContent=d.error||'Failed';"
"e.style.display='block';}\n"
"  }).catch(()=>{var e=document.getElementById('err');"
"e.textContent='Connection error';e.style.display='block';});\n"
"}\n"
"// Check if setup needed\n"
"fetch('/api/auth/status').then(r=>r.json()).then(d=>{\n"
"  if(d.needs_setup){\n"
"    document.getElementById('loginForm').innerHTML=\n"
"    '<p>First-run setup required.</p>'+\n"
"    '<input type=\"text\" id=\"user\" placeholder=\"Choose username\" value=\"admin\">'+\n"
"    '<input type=\"password\" id=\"pass\" placeholder=\"Choose password (8+ chars)\">'+\n"
"    '<button onclick=\"doSetup()\">Create Admin Account</button>'+\n"
"    '<p class=\"error\" id=\"err\"></p>';\n"
"  }\n"
"});\n"
"function doSetup(){\n"
"  var u=document.getElementById('user').value;\n"
"  var p=document.getElementById('pass').value;\n"
"  fetch('/api/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({username:u,password:p})}).then(r=>r.json()).then(d=>{\n"
"    if(d.token){localStorage.setItem('mgmt_token',d.token);"
"document.getElementById('loginForm').innerHTML="
"'<p style=\"color:#3fb950\">Setup complete!</p>';}\n"
"    else{var e=document.getElementById('err');e.textContent=d.error||'Failed';"
"e.style.display='block';}\n"
"  });\n"
"}\n"
"</script></body></html>\n";

static const embedded_asset_t embedded_assets[] = {
    { "index.html", asset_index_html, sizeof(asset_index_html) - 1 },
};

static const int embedded_asset_count = 1;

const embedded_asset_t* find_embedded_asset(const char *path) {
    if (!path) return NULL;
    for (int i = 0; i < embedded_asset_count; i++) {
        if (strcmp(embedded_assets[i].path, path) == 0) {
            return &embedded_assets[i];
        }
    }
    return NULL;
}

int get_embedded_asset_count(void) {
    return embedded_asset_count;
}
