#!/usr/bin/env bash
# xdr-agent - Modular XDR endpoint security agent for Linux
# Copyright (C) 2026  Diego A. Guillen-Rosaperez
# SPDX-License-Identifier: AGPL-3.0
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:-$(cat "${ROOT_DIR}/VERSION")}"
ARCH_INPUT="${2:-amd64}"
DIST_DIR="${ROOT_DIR}/dist"
RPMBUILD_DIR="${DIST_DIR}/rpmbuild"
SPEC_TEMPLATE="${ROOT_DIR}/packaging/rpm/xdr-agent.spec.template"
SPEC_PATH="${RPMBUILD_DIR}/SPECS/xdr-agent.spec"

if ! command -v go >/dev/null 2>&1; then
  echo "go command not found. Install Go to continue."
  exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild command not found. Install rpm-build to continue."
  exit 1
fi

GOARCH_VALUE="${ARCH_INPUT}"
RPM_ARCH="${ARCH_INPUT}"
case "${ARCH_INPUT}" in
  amd64)
    GOARCH_VALUE="amd64"
    RPM_ARCH="x86_64"
    ;;
  arm64)
    GOARCH_VALUE="arm64"
    RPM_ARCH="aarch64"
    ;;
  x86_64)
    GOARCH_VALUE="amd64"
    RPM_ARCH="x86_64"
    ;;
  aarch64)
    GOARCH_VALUE="arm64"
    RPM_ARCH="aarch64"
    ;;
  *)
    echo "unsupported architecture: ${ARCH_INPUT}"
    exit 1
    ;;
esac

echo "[1/4] Building binary for ${GOARCH_VALUE}"
mkdir -p "${DIST_DIR}"
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH_VALUE}" go build \
  -trimpath \
  -ldflags "-s -w -X xdr-agent/internal/buildinfo.Version=${VERSION}" \
  -o "${DIST_DIR}/xdr-agent" \
  "${ROOT_DIR}/cmd/xdr-agent"

echo "[2/4] Preparing rpmbuild workspace"
rm -rf "${RPMBUILD_DIR}"
mkdir -p \
  "${RPMBUILD_DIR}/BUILD" \
  "${RPMBUILD_DIR}/RPMS" \
  "${RPMBUILD_DIR}/SOURCES" \
  "${RPMBUILD_DIR}/SPECS" \
  "${RPMBUILD_DIR}/SRPMS"

install -m 0755 "${DIST_DIR}/xdr-agent" "${RPMBUILD_DIR}/SOURCES/xdr-agent"
install -m 0644 "${ROOT_DIR}/config/config.json" "${RPMBUILD_DIR}/SOURCES/config.json"
install -m 0644 "${ROOT_DIR}/systemd/xdr-agent.service" "${RPMBUILD_DIR}/SOURCES/xdr-agent.service"
install -m 0644 "${ROOT_DIR}/LICENSE" "${RPMBUILD_DIR}/SOURCES/LICENSE"
install -m 0644 "${ROOT_DIR}/AUTHORS" "${RPMBUILD_DIR}/SOURCES/AUTHORS"

sed \
  -e "s/@VERSION@/${VERSION}/g" \
  -e "s/@RPM_ARCH@/${RPM_ARCH}/g" \
  "${SPEC_TEMPLATE}" > "${SPEC_PATH}"

echo "[3/4] Building rpm"
# NOTE: This script is intended for native-arch builds only (e.g. amd64 on
# an x86_64 host).  For cross-architecture RPM builds (e.g. aarch64 on an
# x86_64 CI runner) use the container-native approach in the CI workflow,
# which runs rpmbuild inside a QEMU-emulated arm64 AlmaLinux container.
rpmbuild \
  --define "_topdir ${RPMBUILD_DIR}" \
  --target "${RPM_ARCH}" \
  -bb "${SPEC_PATH}" >/dev/null

echo "[4/4] Done"
# Copy the built RPM to DIST_DIR so callers have a consistent location to
# find it regardless of arch subdirectory (x86_64 vs aarch64).
find "${RPMBUILD_DIR}/RPMS" -type f -name "*.rpm" -exec cp {} "${DIST_DIR}/" \;
find "${DIST_DIR}" -maxdepth 1 -name "*.rpm" -print
