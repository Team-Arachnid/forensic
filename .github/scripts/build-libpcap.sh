#!/bin/sh
# Build a static libpcap for a target the distribution does not package.
#
#   build-libpcap.sh <compiler> <prefix> [configure --host triple]
#
# Needed for two release targets: musl, which no distribution ships a libpcap
# for, and aarch64 cross builds, where the host's package is the wrong
# architecture. Everything else uses the system library.
#
# The tarball digest is pinned by PCAP_SHA256 in the release workflow. A release
# binary must not depend on whatever tcpdump.org served that morning.
set -eu

CC_BIN="$1"
PREFIX="$2"
HOST="${3:-}"
VERSION="${PCAP_VERSION:-1.10.5}"

[ -f "$PREFIX/lib/libpcap.a" ] && { echo "libpcap already built at $PREFIX"; exit 0; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
curl -fsSLO "https://www.tcpdump.org/release/libpcap-$VERSION.tar.gz"

if [ -n "${PCAP_SHA256:-}" ]; then
    echo "$PCAP_SHA256  libpcap-$VERSION.tar.gz" | sha256sum -c - \
        || { echo "libpcap tarball digest does not match the pin; refusing to build" >&2; exit 1; }
else
    echo "warning: PCAP_SHA256 is unset, so the tarball is unverified" >&2
fi

tar xf "libpcap-$VERSION.tar.gz"
cd "libpcap-$VERSION"

# The optional back-ends are all disabled: they pull in D-Bus, libnl, libusb and
# RDMA, none of which a forensic capture needs and every one of which is another
# shared object a "static" binary would end up needing at runtime.
set -- --prefix="$PREFIX" \
       --enable-shared=no \
       --without-libnl \
       --disable-dbus \
       --disable-rdma \
       --disable-bluetooth \
       --disable-usb
[ -n "$HOST" ] && set -- "$@" --host="$HOST"

CC="$CC_BIN" ./configure "$@"
make -j"$(nproc)"
make install
echo "libpcap $VERSION installed to $PREFIX"
