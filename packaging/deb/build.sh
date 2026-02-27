#!/usr/bin/env bash
# xdr-agent - Modular XDR endpoint security agent for Linux
# Copyright (C) 2026  Diego A. Guillen-Rosaperez
# SPDX-License-Identifier: AGPL-3.0
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:-$(cat "${ROOT_DIR}/VERSION")}"
ARCH="${2:-amd64}"
PKG_NAME="xdr-agent"
DIST_DIR="${ROOT_DIR}/dist"
BIN_PATH="${DIST_DIR}/xdr-agent"
PKG_ROOT="${DIST_DIR}/${PKG_NAME}_${VERSION}_${ARCH}"
KEEP_STAGING="${KEEP_STAGING:-0}"

echo "[1/4] Building binary"
mkdir -p "${DIST_DIR}"

GOARCH_VALUE="${ARCH}"
if [[ "${ARCH}" == "arm64" ]]; then
  GOARCH_VALUE="arm64"
elif [[ "${ARCH}" == "amd64" ]]; then
  GOARCH_VALUE="amd64"
fi

CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH_VALUE}" go build \
  -trimpath \
  -ldflags "-s -w -X xdr-agent/internal/buildinfo.Version=${VERSION}" \
  -o "${BIN_PATH}" \
  "${ROOT_DIR}/cmd/xdr-agent"

echo "[2/4] Preparing package filesystem"
rm -rf "${PKG_ROOT}" "${PKG_ROOT}.deb"
mkdir -p \
  "${PKG_ROOT}/DEBIAN" \
  "${PKG_ROOT}/usr/bin" \
  "${PKG_ROOT}/usr/share/xdr-agent" \
  "${PKG_ROOT}/usr/share/bash-completion/completions" \
  "${PKG_ROOT}/usr/lib/systemd/system-preset" \
  "${PKG_ROOT}/etc/xdr-agent" \
  "${PKG_ROOT}/lib/systemd/system" \
  "${PKG_ROOT}/var/lib/xdr-agent"

install -m 0755 "${BIN_PATH}" "${PKG_ROOT}/usr/bin/xdr-agent"
install -m 0644 "${ROOT_DIR}/config/config.json" "${PKG_ROOT}/etc/xdr-agent/config.json"
install -m 0644 "${ROOT_DIR}/config/config.json" "${PKG_ROOT}/usr/share/xdr-agent/config.default.json"
install -m 0644 "${ROOT_DIR}/packaging/bash_completion/xdr-agent" "${PKG_ROOT}/usr/share/bash-completion/completions/xdr-agent"
install -m 0644 "${ROOT_DIR}/packaging/systemd-preset/90-xdr-agent.preset" "${PKG_ROOT}/usr/lib/systemd/system-preset/90-xdr-agent.preset"
install -m 0644 "${ROOT_DIR}/systemd/xdr-agent.service" "${PKG_ROOT}/lib/systemd/system/xdr-agent.service"

mkdir -p "${PKG_ROOT}/usr/share/doc/xdr-agent"
install -m 0644 "${ROOT_DIR}/LICENSE" "${PKG_ROOT}/usr/share/doc/xdr-agent/copyright"
install -m 0644 "${ROOT_DIR}/AUTHORS" "${PKG_ROOT}/usr/share/doc/xdr-agent/AUTHORS"

cat > "${PKG_ROOT}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: XDR Team <xdr@example.com>
Depends: systemd, bash-completion
Description: Lightweight XDR agent (identity and enrollment)
 A minimal host agent that establishes identity and enrolls into a control plane.
EOF

cat > "${PKG_ROOT}/DEBIAN/conffiles" <<EOF
/etc/xdr-agent/config.json
EOF

install -m 0755 "${ROOT_DIR}/packaging/deb/postinst" "${PKG_ROOT}/DEBIAN/postinst"
install -m 0755 "${ROOT_DIR}/packaging/deb/prerm" "${PKG_ROOT}/DEBIAN/prerm"

echo "[3/4] Building .deb"
dpkg-deb --build --root-owner-group "${PKG_ROOT}" >/dev/null

if [[ "${KEEP_STAGING}" != "1" ]]; then
  rm -rf "${PKG_ROOT}"
fi

echo "[4/4] Done"
echo "Package created: ${PKG_ROOT}.deb"
if [[ "${KEEP_STAGING}" == "1" ]]; then
  echo "Staging directory kept: ${PKG_ROOT}"
else
  echo "Staging directory removed: ${PKG_ROOT}"
fi
