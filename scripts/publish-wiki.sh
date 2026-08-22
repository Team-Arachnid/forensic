#!/usr/bin/env bash
# Publish docs/wiki/ to the GitHub wiki at <repo>/wiki.
#
# The wiki is a separate git repository (<repo>.wiki.git) with its own link
# rules, so the pages cannot just be copied across:
#
#   - a wiki page is addressed by filename without the extension, so
#     `[x](01-Getting-Started.md)` has to become `[x](01-Getting-Started)`;
#   - a link out of the wiki and into the repo has no relative path that
#     resolves, so `../../README.md` has to become an absolute blob URL.
#
# GitHub creates <repo>.wiki.git only after the first page is saved through the
# web UI. There is no API for it, so if this script reports the wiki is
# uninitialised, open <repo>/wiki, save any page, and run it again.

set -euo pipefail

REPO="${REPO:-ArachnidGs/forensic}"
BRANCH="${BRANCH:-main}"
SRC="${SRC:-$(cd "$(dirname "$0")/.." && pwd)/docs/wiki}"
BLOB="https://github.com/$REPO/blob/$BRANCH"

[ -d "$SRC" ] || { echo "no wiki source at $SRC" >&2; exit 1; }

TOKEN="$(gh auth token)"
REMOTE="https://x-access-token:${TOKEN}@github.com/${REPO}.wiki.git"

if ! git ls-remote "$REMOTE" >/dev/null 2>&1; then
    cat >&2 <<EOF
The wiki for $REPO has not been initialised.

GitHub creates the wiki repository only when the first page is saved from the
web UI, and exposes no API to do it. Open:

    https://github.com/$REPO/wiki

click "Create the first page", save anything at all (this script overwrites it),
then run this again.
EOF
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
git clone --quiet --depth 1 "$REMOTE" "$WORK/wiki"

# Drop the pages we are about to replace, so a page deleted from docs/wiki/
# disappears from the published wiki too rather than lingering.
find "$WORK/wiki" -maxdepth 1 -name '*.md' -delete

for src in "$SRC"/*.md; do
    name="$(basename "$src")"
    # Order matters: rewrite the way out of the wiki first, so the .md strip
    # below cannot chew the extension off a repo file URL. The delimiter has to
    # be something no pattern contains — '#' would collide with the anchors.
    sed -E \
        -e "s|\]\(\.\./\.\./|](${BLOB}/|g" \
        -e "s|\]\(\.\./|](${BLOB}/docs/|g" \
        -e "s|\]\(${BLOB}/([^)]*)/\)|](https://github.com/${REPO}/tree/${BRANCH}/\1/)|g" \
        -e 's|\]\(([A-Za-z0-9_-]+)\.md(#[^)]*)?\)|](\1\2)|g' \
        "$src" > "$WORK/wiki/$name"
done

cd "$WORK/wiki"
git add -A
if git diff --cached --quiet; then
    echo "wiki already up to date"
    exit 0
fi
git -c user.name="${GIT_AUTHOR_NAME:-$(git config user.name)}" \
    -c user.email="${GIT_AUTHOR_EMAIL:-$(git config user.email)}" \
    commit --quiet -m "docs: sync wiki from docs/wiki@$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo local)"
git push --quiet origin HEAD
echo "published $(ls -1 ./*.md | wc -l) pages to https://github.com/$REPO/wiki"
