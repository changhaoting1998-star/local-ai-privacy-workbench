#!/bin/sh
# Compile locally using Apple frameworks already shipped with this Mac; no download.
set -eu
cd "$(dirname "$0")/.."
mkdir -p backend/bin
BUILD_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/pg-swift-build.XXXXXX")"
trap 'rm -rf "$BUILD_CACHE"' EXIT HUP INT TERM
/usr/bin/swiftc -O -module-cache-path "$BUILD_CACHE" scripts/pdf_vision.swift -o backend/bin/pdf-vision
