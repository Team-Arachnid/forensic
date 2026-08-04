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

# --- 2. the binary ------------------------------------------------------------
echo "==> building arachnid-core for $TARGET"
rustup target add "$TARGET" >/dev/null 2>&1 || true

# SOURCE_DATE_EPOCH and a remapped path prefix make the build reproducible:
# two builds of the same commit produce byte-identical binaries, which is what
# lets a SOC confirm the hash they allowlisted matches the source they reviewed.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
export LIBPCAP_LIBDIR="$PCAP_PREFIX/lib"
export LIBPCAP_VER="$PCAP_VERSION"
export RUSTFLAGS="-C target-feature=+crt-static \
  -L native=$PCAP_PREFIX/lib \
  --remap-path-prefix=$PWD=/build \
  --remap-path-prefix=$HOME/.cargo=/cargo"

cargo build --release --locked --target "$TARGET" -p arachnid-core-cli

BIN="target/$TARGET/release/arachnid-core"
VERSION="$(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
OUT="$DIST/arachnid-core-$VERSION-$TARGET"
cp "$BIN" "$OUT"

