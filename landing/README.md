# PQ-TLS Server Landing Page

This directory contains the landing page for pq-tls.com (or similar domain).

## Files

| File | Purpose |
|------|---------|
| `index.html` | Single-page landing page (dark theme, Axeni-inspired) |

## Deployment

### Option 1: GitHub Pages

Push the contents of this directory to a `gh-pages` branch:

```bash
git subtree push --prefix landing origin gh-pages
```

Configure GitHub Pages in your repo settings to serve from the `gh-pages` branch. Available at:

```
https://vamshikrishnaDoddikadi.github.io/pq-tls-server/
```

### Option 2: Custom Domain

1. Buy `pq-tls.com` or `quantumtls.com` from your preferred registrar
2. Point DNS to GitHub Pages IPs (or your own server):
   ```
   185.199.108.153
   185.199.109.153
   185.199.110.153
   185.199.111.153
   ```
3. Add a `CNAME` file with your domain name
4. Configure in GitHub Pages settings

### Option 3: Self-Host

```bash
# Serve with any static file server
docker run -p 80:80 -v $(pwd):/usr/share/nginx/html:ro nginx:alpine
```

## TODO

- [ ] Buy domain name
- [ ] Set up GitHub Pages or hosting
- [ ] Add analytics (Plausible or Umami — privacy-focused)
- [ ] Add a "Request Demo" form (email capture)
- [ ] Add a mailing list signup
