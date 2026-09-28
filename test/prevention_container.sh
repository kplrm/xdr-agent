#!/usr/bin/env bash
# Exercise real fanotify permission decisions inside a disposable container.
set -euo pipefail
cd "$(dirname "$0")/.."
staging="$(mktemp -d)"
container="xdr-fanotify-smoke-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [ -f "$staging/image.id" ]; then docker image rm -f "$(cat "$staging/image.id")" >/dev/null 2>&1 || true; fi
  rm -rf "$staging"
}
trap cleanup EXIT
CGO_ENABLED=0 "${GO:-go}" test -c -o "$staging/fanotify.test" ./internal/platform/linux
CGO_ENABLED=0 "${GO:-go}" build -o "$staging/fixture" ./test/testdata/exec_exit0.go
cat > "$staging/Dockerfile" <<'EOF'
FROM scratch
COPY fanotify.test /test
COPY fixture /fixture
ENTRYPOINT ["/test"]
EOF
docker build --network none --iidfile "$staging/image.id" -q "$staging" >/dev/null
timeout --signal=TERM --kill-after=5s 30s docker run --rm --name "$container" \
  --network none --read-only --tmpfs /tmp:rw,exec,size=64m,mode=1777 \
  --cpus=1 --memory=256m --pids-limit=64 \
  --cap-add SYS_ADMIN --security-opt seccomp=unconfined \
  -e XDR_REQUIRE_FANOTIFY=1 -e XDR_EXEC_FIXTURE=/fixture \
  "$(cat "$staging/image.id")" -test.run '^TestExecGuardPrivileged' -test.v
