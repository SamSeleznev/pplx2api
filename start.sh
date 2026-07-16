#!/bin/bash
# Stop and remove existing container if it exists
docker rm -f pplx 2>/dev/null || true

# Build local image
docker build -t pplx2api:local .

# Run the container
docker run -d \
  --name pplx \
  -p 8181:8080 \
  --env-file .env \
  pplx2api:local

# Make pplx reachable from the SkillBrain backend container by DNS name `pplx`.
docker network connect skillbrain_bot_app-network pplx 2>/dev/null || true

echo "Container started. Logs:"
sleep 2
docker logs pplx
