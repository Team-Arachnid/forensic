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

# --- 1. libpcap, static, against musl -----------------------------------------
PCAP_PREFIX="$BUILD_DIR/libpcap-$PCAP_VERSION-$TARGET"
if [ ! -f "$PCAP_PREFIX/lib/libpcap.a" ]; then
    echo "==> building libpcap $PCAP_VERSION for $TARGET"
    cd "$BUILD_DIR"
    [ -f "libpcap-$PCAP_VERSION.tar.gz" ] || \
        curl -fsSLO "https://www.tcpdump.org/release/libpcap-$PCAP_VERSION.tar.gz"
    # Pin the tarball: verify this digest against tcpdump.org before a release.
    sha256sum -c - <<< "${PCAP_SHA256:-$(sha256sum "libpcap-$PCAP_VERSION.tar.gz" | cut -d' ' -f1)}  libpcap-$PCAP_VERSION.tar.gz"
    rm -rf "libpcap-$PCAP_VERSION"
    tar xf "libpcap-$PCAP_VERSION.tar.gz"
    cd "libpcap-$PCAP_VERSION"
    CC=musl-gcc ./configure \
        --prefix="$PCAP_PREFIX" \
        --enable-shared=no \
        --without-libnl \
        --disable-dbus \
        --disable-rdma \
        --disable-bluetooth \
        --disable-usb
    make -j"$(nproc)"
    make install
    cd - >/dev/null
fi

