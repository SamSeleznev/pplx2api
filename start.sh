#!/bin/bash
# Stop and remove existing container if it exists
docker rm -f pplx 2>/dev/null || true

# Run the container
docker run -d \
  --name pplx \
  -p 8181:8080 \
  --env-file .env \
  ghcr.io/yushangxiao/pplx2api:latest

# Make pplx reachable from the SkillBrain backend container by DNS name `pplx`.
docker network connect skillbrain_bot_app-network pplx 2>/dev/null || true

echo "Container started. Logs:"
sleep 2
docker logs pplx
