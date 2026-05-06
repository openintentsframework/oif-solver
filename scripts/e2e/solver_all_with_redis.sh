#!/usr/bin/env bash
set -euo pipefail

container_name="${E2E_REDIS_CONTAINER_NAME:-oif-solver-e2e-redis}"
redis_port="${E2E_REDIS_PORT:-6379}"
redis_image="${E2E_REDIS_IMAGE:-redis:7-alpine}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
solver_all="${script_dir}/solver_all.sh"

run_solver_all() {
  cd "${repo_root}"
  "${solver_all}"
}

# Honor a pre-set REDIS_URL before requiring Docker — otherwise runners
# without Docker can't take advantage of an externally provisioned Redis.
if [ -n "${REDIS_URL:-}" ]; then
  run_solver_all
  exit $?
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required when REDIS_URL is not already set" >&2
  exit 1
fi

cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
docker run \
  --detach \
  --name "${container_name}" \
  --publish "127.0.0.1:${redis_port}:6379" \
  "${redis_image}" >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${container_name}" redis-cli ping >/dev/null 2>&1; then
    export REDIS_URL="redis://127.0.0.1:${redis_port}"
    run_solver_all
    exit $?
  fi
  sleep 1
done

echo "timed out waiting for Redis container ${container_name}" >&2
exit 1
