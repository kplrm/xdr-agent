#!/usr/bin/env bash
# xdr-agent - Modular XDR endpoint security agent for Linux
# Copyright (C) 2026  Diego A. Guillen-Rosaperez
# SPDX-License-Identifier: AGPL-3.0
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$(cat "${ROOT_DIR}/VERSION")}"
ARCHES="${ARCHES:-amd64 arm64}"

echo "Building xdr-agent packages"
echo "  version : ${VERSION}"
echo "  arches  : ${ARCHES}"

for arch in ${ARCHES}; do
  echo "--> deb/${arch}"
  bash "${ROOT_DIR}/packaging/deb/build.sh" "${VERSION}" "${arch}"
done

echo "All package builds completed."
