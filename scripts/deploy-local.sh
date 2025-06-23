#!/bin/bash
# Quick local Kubernetes deployment script for testing
# Requires: kubectl, kind (optional for local cluster)

set -e

echo "🚀 Tarnished API Kubernetes Deployment Script"
echo "=============================================="

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is required but not installed"
    exit 1
fi

# Function to check if cluster is available
check_cluster() {
    if kubectl cluster-info &> /dev/null; then
        echo "✅ Kubernetes cluster is accessible"
        kubectl cluster-info
        return 0
    else
        echo "❌ No Kubernetes cluster found"
        return 1
    fi
}

# Function to create local kind cluster if needed
create_kind_cluster() {
    if command -v kind &> /dev/null; then
        echo "🔧 Creating local kind cluster..."
        kind create cluster --name tarnished-api-local
        kubectl cluster-info --context kind-tarnished-api-local
    else
        echo "❌ kind is not installed. Please install kind or configure kubectl for your cluster"
        exit 1
    fi
}

# Check for cluster or offer to create one
if ! check_cluster; then
    read -p "Would you like to create a local kind cluster? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_kind_cluster
    else
        echo "Please configure kubectl to access your Kubernetes cluster and try again"
        exit 1
    fi
fi

echo ""
echo "📦 Deploying Tarnished API..."

# Apply manifests
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

echo ""
echo "⏳ Waiting for deployment to be ready..."
kubectl rollout status deployment/tarnished-api --timeout=300s

echo ""
echo "🔍 Checking deployment status..."
kubectl get pods -l app=tarnished-api
kubectl get svc tarnished-api-service

echo ""
echo "🧪 Testing health endpoint..."
kubectl port-forward svc/tarnished-api-service 8080:80 &
PORT_FORWARD_PID=$!

# Wait a moment for port-forward to establish
sleep 5

if curl -f http://localhost:8080/api/health; then
    echo ""
    echo "✅ Health check successful!"
else
    echo ""
    echo "❌ Health check failed"
fi

# Cleanup port-forward
kill $PORT_FORWARD_PID 2>/dev/null || true

echo ""
echo "🎉 Deployment completed successfully!"
echo ""
echo "To access the API:"
echo "  kubectl port-forward svc/tarnished-api-service 8080:80"
echo "  curl http://localhost:8080/api/health"
echo ""
echo "To view logs:"
echo "  kubectl logs -l app=tarnished-api -f"
echo ""
echo "To cleanup:"
echo "  kubectl delete -f k8s/"
echo "  kind delete cluster --name tarnished-api-local  # if using kind"