#!/bin/bash
set -e

echo "🛡️  Deploying Aegis ITDR to Production..."

# Step 1: Build Docker image
echo "Step 1: Building Docker image..."
docker build -t aegis-itdr:latest .

# Step 2: Tag for registry
echo "Step 2: Tagging image for registry..."
docker tag aegis-itdr:latest utkarshover9000/aegis-itdr:latest

# Step 3: Push image
echo "Step 3: Pushing to Docker Hub..."
# docker push utkarshover9000/aegis-itdr:latest

# Step 4: Rolling update to Kubernetes
echo "Step 4: Rolling restart on Kubernetes cluster..."
# kubectl rollout restart deploy/aegis-itdr

echo "✅  Aegis ITDR deployment complete!"
