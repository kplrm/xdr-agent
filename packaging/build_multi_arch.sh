#!/usr/bin/env bash
# xdr-agent - Modular XDR endpoint security agent for Linux
# Copyright (C) 2026  Diego A. Guillen-Rosaperez
# SPDX-License-Identifier: AGPL-3.0
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$(cat "${ROOT_DIR}/VERSION")}"
ARCHES="${ARCHES:-amd64 arm64}"
FORMATS="${FORMATS:-deb rpm}"

echo "Building xdr-agent packages"
echo "  version : ${VERSION}"
echo "  arches  : ${ARCHES}"
echo "  formats : ${FORMATS}"

for arch in ${ARCHES}; do
  for format in ${FORMATS}; do
    case "${format}" in
      deb)
        echo "--> deb/${arch}"
        bash "${ROOT_DIR}/packaging/deb/build.sh" "${VERSION}" "${arch}"
        ;;
      rpm)
        echo "--> rpm/${arch}"
        bash "${ROOT_DIR}/packaging/rpm/build.sh" "${VERSION}" "${arch}"
        ;;
      *)
        echo "Unknown package format: ${format}"
        exit 1
        ;;
    esac
  done
done

echo "All package builds completed."
