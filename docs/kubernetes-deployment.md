# Kubernetes Deployment Guide

This document describes how to deploy the Tarnished API to a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (local: minikube, kind, k3s; cloud: GKE, EKS, AKS)
- `kubectl` configured to access your cluster
- (Optional) `kustomize` for configuration management
- (Optional) NGINX Ingress Controller for external access

## Quick Start

### 1. Deploy using kubectl

```bash
# Apply all manifests
kubectl apply -f ./k8s/

# Or use kustomize
kubectl apply -k ./k8s/

# Or use the provided script for local testing
./scripts/deploy-local.sh
```

### 2. Verify deployment

```bash
# Check deployment status
kubectl rollout status deployment/tarnished-api

# Check pods
kubectl get pods -l app=tarnished-api

# Check service
kubectl get svc tarnished-api-service
```

### 3. Test the API

#### Port forwarding (for testing)
```bash
# Forward local port to service
kubectl port-forward svc/tarnished-api-service 8080:80

# Test health endpoint
curl http://localhost:8080/api/health
```

#### Using ingress (if configured)
```bash
# Add to /etc/hosts (for local testing)
echo "127.0.0.1 tarnished-api.local" | sudo tee -a /etc/hosts

# Test via ingress
curl https://tarnished-api.local/api/health
```

## Configuration

### Environment Variables

The deployment uses ConfigMaps and Secrets for configuration:

#### ConfigMap (`k8s/configmap.yaml`)
- `rust-log`: Logging level (default: "info,auth_audit=info")
- `log-format`: Log format (default: "json")  
- `metrics-enabled`: Enable Prometheus metrics (default: "true")
- Security headers, rate limiting, and authentication settings

#### Secrets (`k8s/secret.yaml`)
- `hmac-secret`: HMAC signing secret
- `new-relic-license-key`: New Relic license key
- `new-relic-account-id`: New Relic account ID

**Important**: Update the secret values before deploying to production:

```bash
# Encode secrets (replace with actual values)
echo -n "your-actual-hmac-secret" | base64
echo -n "your-new-relic-license-key" | base64
echo -n "your-new-relic-account-id" | base64
```

### Customization with Kustomize

Modify `k8s/kustomization.yaml` to:

- Change replica count
- Update image tag
- Set namespace
- Add additional labels

Example for production:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - deployment.yaml
  - service.yaml
  - configmap.yaml
  - secret.yaml
  - ingress.yaml

images:
  - name: ghcr.io/markcoleman/tarnished-api
    newTag: v1.2.3  # Use specific version in production

replicas:
  - name: tarnished-api
    count: 3  # Scale for production

namespace: tarnished-api-prod
```

## Monitoring and Troubleshooting

### View logs
```bash
# View logs from all pods
kubectl logs -l app=tarnished-api

# Follow logs from a specific pod
kubectl logs -f deployment/tarnished-api

# View logs from previous container (if crashed)
kubectl logs -l app=tarnished-api --previous
```

### Check service endpoints
```bash
# List endpoints
kubectl get endpoints tarnished-api-service

# Describe service for troubleshooting
kubectl describe svc tarnished-api-service
```

### Debug networking
```bash
# Test service from within cluster
kubectl run debug --image=curlimages/curl --rm -it --restart=Never -- \
  curl http://tarnished-api-service.default.svc.cluster.local/api/health

# Check ingress status
kubectl describe ingress tarnished-api-ingress
```

### Health checks
```bash
# Check readiness probe
kubectl exec deployment/tarnished-api -- curl -f http://localhost:8080/api/health

# Check liveness probe status
kubectl describe pod -l app=tarnished-api
```

## Scaling

### Manual scaling
```bash
# Scale to 5 replicas
kubectl scale deployment tarnished-api --replicas=5

# Check scaling status
kubectl get deployment tarnished-api
```

### Horizontal Pod Autoscaler (HPA)
```bash
# Create HPA (requires metrics-server)
kubectl autoscale deployment tarnished-api --cpu-percent=70 --min=2 --max=10

# Check HPA status
kubectl get hpa
```

## Security Considerations

### Pod Security
- Runs as non-root user (UID 1000)
- Read-only root filesystem
- Drops all capabilities
- No privilege escalation

### Network Security
- Uses ClusterIP service by default (internal only)
- Ingress configured with SSL redirect and security headers
- HTTPS enforced when using ingress

### Secrets Management
- Sensitive data stored in Kubernetes secrets
- Secrets mounted as environment variables
- Consider using external secret management (e.g., HashiCorp Vault, AWS Secrets Manager)

## Production Recommendations

1. **Use specific image tags** instead of `latest`
2. **Configure resource limits** based on your workload
3. **Set up monitoring** with Prometheus/Grafana
4. **Configure backup** for persistent data (if any)
5. **Implement network policies** for additional security
6. **Use external secret management**
7. **Set up proper logging aggregation**
8. **Configure alerts** for critical metrics

## Cleanup

```bash
# Remove all resources
kubectl delete -f ./k8s/

# Or using kustomize
kubectl delete -k ./k8s/
```