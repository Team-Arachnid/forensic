#!/bin/sh
# Arachnid Forensic — installer for macOS and Linux.
#
# You are encouraged to read this before running it. That is not a formality:
# this suite asks SOCs to allowlist a binary that does forensic things to a
# host, and a project making that request should not also ask you to pipe an
# unread script into a shell.
#
#   curl -fsSL https://raw.githubusercontent.com/ArachnidGs/forensic/main/install.sh -o install.sh
#   sh install.sh
#
# Reading it first is encouraged but is your call, not a step you have to get
# past: `less install.sh` before that second line, or open it in an editor.
#
# What it does, in order:
#   1. works out this machine's OS, architecture and libc
#   2. downloads the matching release binary, its SHA256SUMS, and the detached
#      signature over SHA256SUMS
#   3. verifies the signature against a key pinned in this file, then verifies
#      the binary's digest against the signed SHA256SUMS. It stops on either
#      failure and installs nothing
#   4. installs to a per-user directory, adds it to PATH only if it is missing,
#      and prints the exact line it added and the file it added it to
#
# What it does not do: no telemetry, no analytics, no phone-home beyond the
# downloads above. It never installs third-party drivers, and it never elevates
# privileges without asking you first, in words, for that specific command.
#
# Uninstall with:  arachnid-cli self uninstall

set -eu

REPO="ArachnidGs/forensic"
BIN="arachnid-cli"
MARKER="# added by arachnid-cli installer"

# Minisign public key for release artifacts. This is the trust anchor: the whole
# verification chain reduces to whether this line is the project's real key.
#
# The installer fails closed if this is ever emptied, rather than falling back to
# "checksum only" — a checksum fetched over the same channel as the artifact
# proves the download was not corrupted and nothing at all about where it came
# from. Rotating it is a release, not a patch; see release/README.md.
PUBKEY="${ARACHNID_PUBKEY:-RWT8KhRGhzRZ4gmiGJHOgKJOfZCY6dxDG/SIew+5RDH0LOkPXHFJENGh}"

say()  { printf '%s\n' "$*"; }
step() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

need() {
    have "$1" || die "$1 is required but not installed."
}

# --------------------------------------------------------------------------
# Platform
# --------------------------------------------------------------------------

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        *) die "unsupported architecture: $arch. Build from source with: cargo install --path crates/arachnid-cli" ;;
    esac

    case "$os" in
        Darwin)
            TARGET="$arch-apple-darwin"
            ;;
        Linux)
            # A musl host (Alpine, and most containers) cannot run a glibc
            # build, and the failure it gives is "not found" on a file that is
            # plainly there — so this is worth getting right rather than
            # defaulting.
            if is_musl; then
                TARGET="$arch-unknown-linux-musl"
            else
                TARGET="$arch-unknown-linux-gnu"
            fi
            ;;
        *)
            die "unsupported operating system: $os. Windows users: use install.ps1."
            ;;
    esac
}

is_musl() {
    # ldd prints its own libc's identity; on musl that names musl. Checking for
    # the loader by path is the fallback for images with no ldd at all.
    if have ldd && ldd --version 2>&1 | grep -qi musl; then
        return 0
    fi
    for loader in /lib/ld-musl-*.so.1; do
        if [ -e "$loader" ]; then return 0; fi
    done
    return 1
}

# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------

fetch() {
    # $1 url, $2 destination
    if have curl; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif have wget; then
        wget -qO "$2" "$1"
    else
        die "need curl or wget to download."
    fi
}

# Fetch to a file and report the HTTP status, so "no release exists" and "the
# network is down" stop looking like the same failure. Deliberately without
# curl's -f: a 404 body is what tells us which of the two it was.
fetch_status() {
    if have curl; then
        curl -sSL --proto '=https' --tlsv1.2 -o "$2" -w '%{http_code}' "$1" 2>/dev/null \
            || printf '000'
    elif wget -qO "$2" "$1"; then
        printf '200'
    else
        # wget does not hand back a status without parsing its stderr, so an
        # error here is reported as "unknown" rather than guessed at.
        printf '???'
    fi
}

# Resolve the release to install into $TAG.
#
# Not a command substitution: `die` inside one exits the subshell, and the
# specific diagnosis would be swallowed on the way out.
resolve_tag() {
    if [ -n "${ARACHNID_VERSION:-}" ]; then
        TAG="$ARACHNID_VERSION"
        return
    fi

    status="$(fetch_status "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json")"
    case "$status" in
        200) ;;
        404) die "this repository has no published releases yet, so there is nothing to install.

Build it from source in the meantime:
  git clone https://github.com/$REPO.git
  cd forensic && cargo install --path crates/arachnid-cli

Or watch https://github.com/$REPO/releases for the first one." ;;
        403 | 429) die "GitHub rate-limited this request (HTTP $status). Wait a few minutes, or
install a specific version:  ARACHNID_VERSION=v0.1.0 sh install.sh" ;;
        000) die "could not reach api.github.com. Check network access and any proxy, or
install a specific version:  ARACHNID_VERSION=v0.1.0 sh install.sh" ;;
        *) die "could not read the release list (HTTP $status). Install a specific version
instead:  ARACHNID_VERSION=v0.1.0 sh install.sh" ;;
    esac

    TAG="$(sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n1)"
    [ -n "$TAG" ] || die "the releases API answered, but with no tag_name. Install a specific
version instead:  ARACHNID_VERSION=v0.1.0 sh install.sh"
}

# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

verify_signature() {
    # $1 signed file, $2 detached signature
    [ -n "$PUBKEY" ] || die "this installer has no release key pinned, so a download cannot be
verified and will not be installed. See release/README.md, or install from source:
  cargo install --git https://github.com/$REPO arachnid-cli"

    if have minisign; then
        printf '%s\n' "$PUBKEY" > "$TMP/minisign.pub"
        minisign -Vm "$1" -x "$2" -p "$TMP/minisign.pub" >/dev/null \
            || die "signature verification FAILED. The download does not come from the release
key pinned in this installer. Nothing has been installed. Do not run the
downloaded file; report this."
        say "    signature: verified with minisign"
        return 0
    fi

    if have signify || have signify-openbsd; then
        sig_tool="$(command -v signify || command -v signify-openbsd)"
        printf '%s\n' "$PUBKEY" > "$TMP/minisign.pub"
        "$sig_tool" -V -p "$TMP/minisign.pub" -x "$2" -m "$1" >/dev/null 2>&1 \
            || die "signature verification FAILED. Nothing has been installed."
        say "    signature: verified with signify"
        return 0
    fi

    die "no signature verification tool found, and this installer will not skip the check.

Install one, then re-run:
  macOS          brew install minisign
  Debian/Ubuntu  sudo apt install minisign
  Fedora         sudo dnf install minisign
  Arch           sudo pacman -S minisign
  Alpine         sudo apk add minisign

Or download the release, its SHA256SUMS and SHA256SUMS.minisig by hand from
https://github.com/$REPO/releases and verify them yourself."
}

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "need sha256sum or shasum to verify the download."
    fi
}

verify_digest() {
    # $1 file, $2 checksums file, $3 name as listed
    want="$(grep -E "[ *]$3\$" "$2" | head -n1 | cut -d' ' -f1)"
    [ -n "$want" ] || die "$3 is not listed in SHA256SUMS; refusing to install it."
    got="$(sha256_of "$1")"
    [ "$want" = "$got" ] || die "checksum MISMATCH for $3.
  expected $want
  got      $got
Nothing has been installed. Do not run the downloaded file; report this."
    say "    sha256:    $got"
}

# --------------------------------------------------------------------------
# Install location
# --------------------------------------------------------------------------

choose_dir() {
    if [ -n "${ARACHNID_INSTALL_DIR:-}" ]; then
        INSTALL_DIR="$ARACHNID_INSTALL_DIR"
        return
    fi
    # macOS convention is /usr/local/bin when it is already writable — but never
    # by acquiring root to make it so. A per-user install needs no privileges
    # and is trivial to remove.
    if [ "$(uname -s)" = "Darwin" ] && [ -w /usr/local/bin ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
    fi
}

# --------------------------------------------------------------------------
# PATH
# --------------------------------------------------------------------------

on_path() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_for_shell() {
    # The login shell, not the shell running this script: `sh install.sh` from a
    # zsh session must still edit .zshrc.
    login_shell="$(basename "${SHELL:-/bin/sh}")"
    case "$login_shell" in
        zsh)  printf '%s\n' "${ZDOTDIR:-$HOME}/.zshrc" ;;
        fish) printf '%s\n' "$HOME/.config/fish/config.fish" ;;
        bash)
            # .bash_profile wins when it exists, because bash reads only that
            # one on a login shell and .bashrc would never be sourced.
            if [ -f "$HOME/.bash_profile" ]; then
                printf '%s\n' "$HOME/.bash_profile"
            else
                printf '%s\n' "$HOME/.bashrc"
            fi
            ;;
        *) printf '%s\n' "$HOME/.profile" ;;
    esac
}

path_line_for_shell() {
    # SC2016 is the intent, not a slip: this writes a line into the operator's
    # profile that has to contain a literal $PATH, expanded by their shell at
    # login rather than by this script now.
    # shellcheck disable=SC2016
    case "$(basename "${SHELL:-/bin/sh}")" in
        fish) printf 'fish_add_path %s\n' "$1" ;;
        *)    printf 'export PATH="%s:$PATH"\n' "$1" ;;
    esac
}

setup_path() {
    if on_path "$INSTALL_DIR"; then
        PATH_NOTE="$INSTALL_DIR was already on PATH; nothing was changed."
        return
    fi
    profile="$(profile_for_shell)"
    line="$(path_line_for_shell "$INSTALL_DIR")"

    # Idempotent: a second run must not append a second copy.
    if [ -f "$profile" ] && grep -qF "$MARKER" "$profile"; then
        PATH_NOTE="$profile already carries the installer's PATH line; nothing was changed."
        return
    fi

    mkdir -p "$(dirname "$profile")"
    printf '\n%s\n%s\n' "$MARKER" "$line" >> "$profile"
    PATH_NOTE="added to $profile:
      $line
    Open a new shell, or run:  . $profile"
}

# --------------------------------------------------------------------------
# Runtime dependencies
# --------------------------------------------------------------------------

pkg_hint() {
    if have apt-get;   then printf 'sudo apt install %s\n' "$1"
    elif have dnf;     then printf 'sudo dnf install %s\n' "$1"
    elif have pacman;  then printf 'sudo pacman -S %s\n' "$1"
    elif have zypper;  then printf 'sudo zypper install %s\n' "$1"
    elif have apk;     then printf 'sudo apk add %s\n' "$1"
    else printf 'install %s with this system'"'"'s package manager\n' "$1"
    fi
}

check_libpcap() {
    [ "$(uname -s)" = "Linux" ] || return 0
    # Any of these means the runtime library is present. The -dev package is a
    # build-time concern and is deliberately not required here.
    for probe in /usr/lib/libpcap.so.1 /usr/lib64/libpcap.so.1 \
                 /usr/lib/*/libpcap.so.1 /lib/*/libpcap.so.1; do
        if [ -e "$probe" ]; then return 0; fi
    done
    if have ldconfig && ldconfig -p 2>/dev/null | grep -q 'libpcap\.so'; then
        return 0
    fi
    warn "libpcap was not found. Live packet capture will not work until it is installed:
    $(pkg_hint libpcap)
  Everything else — collect, parse-pcap, verify, report, recover, sanitize —
  works without it."
}

offer_setcap() {
    [ "$(uname -s)" = "Linux" ] || return 0
    have setcap || return 0
    say ""
    say "Live capture needs CAP_NET_RAW, or root. The capability is the smaller grant:"
    say "  sudo setcap cap_net_raw,cap_net_admin=eip $INSTALL_DIR/$BIN"
    # Never silently. And never at all without a terminal to answer from, which
    # is what keeps a piped install from blocking forever.
    if [ ! -t 0 ]; then
        say "  (run that yourself when you want capture; not prompting on a non-interactive install)"
        return 0
    fi
    printf 'Run it now with sudo? [y/N] '
    read -r reply
    case "$reply" in
        y | Y | yes | YES)
            if sudo setcap cap_net_raw,cap_net_admin=eip "$INSTALL_DIR/$BIN"; then
                say "  granted."
            else
                warn "setcap failed; run it yourself when you need capture."
            fi
            ;;
        *) say "  skipped." ;;
    esac
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

need uname
need mkdir
need grep
need sed

detect_target
choose_dir

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

step "Arachnid Forensic installer"
say  "    target:    $TARGET"

resolve_tag
VERSION="${TAG#v}"
say  "    release:   $TAG"

# Idempotency: if the installed copy is already this version, stop before
# downloading anything at all.
EXISTING="$INSTALL_DIR/$BIN"
if [ -x "$EXISTING" ]; then
    current="$("$EXISTING" version 2>/dev/null | head -n1 | awk '{print $2}')" || current=""
    if [ "$current" = "$VERSION" ]; then
        step "$BIN $VERSION is already installed at $EXISTING"
        say  "    Nothing to do. Run '$BIN doctor' to check the installation."
        exit 0
    fi
    [ -n "$current" ] && say "    upgrading: $current -> $VERSION"
fi

ASSET="$BIN-$TARGET"
BASE="https://github.com/$REPO/releases/download/$TAG"

step "Downloading"
fetch "$BASE/$ASSET"              "$TMP/$ASSET"     || die "could not download $ASSET for $TAG.
This platform may not have a published binary for this release; see
https://github.com/$REPO/releases"
fetch "$BASE/SHA256SUMS"          "$TMP/SHA256SUMS"
fetch "$BASE/SHA256SUMS.minisig"  "$TMP/SHA256SUMS.minisig"

step "Verifying"
# Signature first: SHA256SUMS is only worth reading once it is known to be ours.
verify_signature "$TMP/SHA256SUMS" "$TMP/SHA256SUMS.minisig"
verify_digest "$TMP/$ASSET" "$TMP/SHA256SUMS" "$ASSET"

step "Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
chmod 0755 "$TMP/$ASSET"
# Move into place last and in one step, so an interrupted install never leaves a
# half-written binary where a working one used to be.
mv -f "$TMP/$ASSET" "$EXISTING"

PATH_NOTE=""
setup_path
check_libpcap
offer_setcap

say ""
step "Installed"
say  "    version:   $VERSION"
say  "    path:      $EXISTING"
say  "    PATH:      $PATH_NOTE"
say  ""
say  "Check it over with:   $BIN doctor"
say  "Remove it later with: $BIN self uninstall"
