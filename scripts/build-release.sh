#!/usr/bin/env bash
# Reproducible, statically linked Linux release build + detached GPG signature.
#
# The Windows counterpart is scripts/build-release.ps1 (Authenticode).
#
# Why libpcap is built from source here: the `pcap` crate links against the
# system libpcap, and no distribution ships a musl static build of it. Building
# it in-tree is what makes a genuinely single-file binary possible. If you skip
# this and build against glibc, you get a working binary with a dynamic libpcap
# dependency — fine for a lab, wrong for a locked-down host.

set -euo pipefail

TARGET="${TARGET:-x86_64-unknown-linux-musl}"
PCAP_VERSION="${PCAP_VERSION:-1.10.5}"
BUILD_DIR="${BUILD_DIR:-$(pwd)/target/release-build}"
DIST="${DIST:-$(pwd)/dist}"
GPG_KEY="${GPG_KEY:-}"

need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need cargo
need musl-gcc
need curl
need tar

mkdir -p "$BUILD_DIR" "$DIST"

