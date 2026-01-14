#!/bin/bash
# Stop and remove existing container if it exists
docker rm -f pplx 2>/dev/null || true

# Run the container
docker run -d \
  --name pplx \
  -p 8181:8080 \
  --env-file .env \
  ghcr.io/yushangxiao/pplx2api:latest

echo "Container started. Logs:"
sleep 2
docker logs pplx
