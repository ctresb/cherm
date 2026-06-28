#!/usr/bin/env bash
# Operate the official Cherm relay as a Docker container (the deployment used on
# srv.cherm.chat — no root / systemd required, just the docker group).
#
#   ./cherm-docker.sh run         build+run the container (idempotent)
#   ./cherm-docker.sh status      container status + recent logs
#   ./cherm-docker.sh logs        follow logs
#   ./cherm-docker.sh maintenance announce maintenance + graceful stop (auto-restarts)
#   ./cherm-docker.sh update      rebuild image, then graceful maintenance restart
#   ./cherm-docker.sh stop        stop (will NOT auto-restart until 'run' again)
#
# Maintenance/update uses `docker exec <c> kill -USR1 1` — NOT `docker kill`,
# which Docker treats as a manual stop and would suppress the restart policy.
# The server then broadcasts a Maintenance event (clients show a local 60s
# countdown + enter waiting-for-server), drains new connections, and exits; the
# `--restart always` policy brings it back. Config + data live in bind mounts and
# are preserved across restarts/updates.
set -euo pipefail

NAME="cherm-server"
IMAGE="cherm-server:0.1.0"
HOME_DIR="${CHERM_DIR:-$HOME/cherm}"
PORT="${CHERM_PORT:-9000}"
VERSION="${CHERM_VERSION:-0.1.0}"

run() {
  mkdir -p "$HOME_DIR/data" "$HOME_DIR/config"
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "==> building $IMAGE"
    docker build -t "$IMAGE" "$HOME_DIR/build"
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" \
    --restart always \
    --user "$(id -u):$(id -g)" \
    -p "0.0.0.0:${PORT}:9000" \
    -v "$HOME_DIR/data:/data" \
    -v "$HOME_DIR/config:/config:ro" \
    "$IMAGE" \
    --addr 0.0.0.0:9000 \
    --db /data/cherm-server.db \
    --instance-key /data/instance.key \
    --config /config/server.json \
    --version "$VERSION"
  sleep 2
  docker ps --filter "name=$NAME" --format '{{.Names}} | {{.Status}} | {{.Ports}}'
}

status() {
  docker ps -a --filter "name=$NAME" --format '{{.Names}} | {{.Status}} | {{.Ports}}'
  echo "restart policy: $(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$NAME" 2>/dev/null || echo n/a)"
  echo "--- recent logs ---"
  docker logs --tail 15 "$NAME" 2>&1 || true
}

maintenance() {
  echo "==> announcing maintenance (clients show 60s countdown) + graceful stop"
  docker exec "$NAME" sh -c 'kill -USR1 1'
  echo "    server will drain + exit, then --restart always brings it back. Clients reconnect."
}

update() {
  echo "==> rebuilding image from $HOME_DIR/build"
  docker build -t "$IMAGE" "$HOME_DIR/build"
  # With a freshly built image of the SAME tag, the restart after graceful exit
  # would still use the running container's image layer; recreate to pick up the
  # new image, but only AFTER the maintenance window so clients are warned.
  echo "==> announcing maintenance + graceful stop"
  docker exec "$NAME" sh -c 'kill -USR1 1' || true
  echo "==> waiting for graceful exit (warning window)…"
  for i in $(seq 1 75); do docker ps --filter "name=$NAME" --format '{{.Status}}' | grep -q Up || break; sleep 1; done
  run
  echo "==> updated. Clients reconnect automatically."
}

stop() { docker stop "$NAME"; }

case "${1:-status}" in
  run) run ;;
  status) status ;;
  logs) docker logs -f "$NAME" ;;
  maintenance) maintenance ;;
  update) update ;;
  stop) stop ;;
  *) echo "usage: $0 {run|status|logs|maintenance|update|stop}"; exit 1 ;;
esac
