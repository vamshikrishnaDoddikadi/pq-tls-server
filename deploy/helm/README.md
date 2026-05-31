# This directory contains the Helm chart for deploying PQ-TLS Server on Kubernetes.

## Prerequisites

- Kubernetes 1.22+
- Helm 3.8+
- Cert-manager (recommended for TLS certificate management)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/vamshikrishnaDoddikadi/pq-tls-server.git
cd pq-tls-server/deploy/helm

# Create a TLS secret with your certificate
kubectl create secret tls pq-tls-tls \
  --cert=/path/to/tls.crt \
  --key=/path/to/tls.key

# Install the chart
helm install pq-tls pq-tls-server \
  --set backends[0].address=my-backend:8080 \
  --set existingTlsSecret=pq-tls-tls

# Or with a custom values file
helm install pq-tls pq-tls-server \
  -f my-values.yaml
```

## Configuration

See [values.yaml](pq-tls-server/values.yaml) for all configuration options.

### Minimal Configuration

The only required values are:

```yaml
backends:
  - address: "my-app:8080"
    weight: 1

# Provide either inline certs:
tls:
  cert: |
    -----BEGIN CERTIFICATE-----
    ...
  key: |
    -----BEGIN PRIVATE KEY-----
    ...

# Or reference an existing Kubernetes TLS secret:
existingTlsSecret: my-tls-secret
```

### Production Configuration

```yaml
replicaCount: 3

backends:
  - address: "backend-v1:8080"
    weight: 3
  - address: "backend-v2:8080"
    weight: 1

groups: "X25519MLKEM768:X25519"

rateLimit:
  perIp: 50
  burst: 100

acl:
  mode: allowlist
  entries:
    - "10.0.0.0/8"
    - "192.168.0.0/16"

resources:
  limits:
    cpu: 4
    memory: 1Gi
  requests:
    cpu: 1
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

serviceMonitor:
  enabled: true
  interval: 30s

ingress:
  enabled: true
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: pq-tls.example.com
      paths:
        - path: /
          pathType: Prefix
```

## Monitoring

The chart exposes Prometheus metrics at `/metrics` on the management port. Enable ServiceMonitor integration with:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
```

This requires the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator) to be installed in the cluster.

## Uninstalling

```bash
helm uninstall pq-tls
```
