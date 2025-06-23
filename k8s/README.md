# Kubernetes Manifests

This directory contains Kubernetes deployment manifests for the Tarnished API.

## Files

- **`deployment.yaml`** - Kubernetes deployment with health/readiness probes
- **`service.yaml`** - ClusterIP service to expose the API internally
- **`ingress.yaml`** - NGINX ingress for external access (optional)
- **`configmap.yaml`** - Configuration values (logging, metrics, security)
- **`secret.yaml`** - Sensitive configuration (HMAC secrets, API keys)
- **`kustomization.yaml`** - Kustomize configuration for easy management

## Quick Start

```bash
# Deploy everything
kubectl apply -k ./k8s/

# Check status
kubectl rollout status deployment/tarnished-api

# Test via port-forward
kubectl port-forward svc/tarnished-api-service 8080:80
curl http://localhost:8080/api/health
```

## Configuration

Update `secret.yaml` with actual values before deploying:

```bash
# Generate base64 encoded secrets
echo -n "your-hmac-secret" | base64
echo -n "your-new-relic-key" | base64
```

See [../docs/kubernetes-deployment.md](../docs/kubernetes-deployment.md) for detailed deployment instructions.