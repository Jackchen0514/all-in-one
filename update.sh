#!/usr/bin/env bash
# One-click update for a panel and/or node installed by install.sh.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Jackchen0514/all-in-one/main/update.sh)
#
# Options (passed to `install.sh update`):
#   --no-hysteria     don't upgrade the hysteria binary
#   --hy-version V    upgrade hysteria to version V instead of the latest (e.g. v2.6.1)
#   --no-anytls       don't upgrade anytls-server
#   --no-ss           don't upgrade shadowsocks-rust
#   --force           reinstall the panel code even if already up to date
#
# Updates the panel code (with a database backup and automatic rollback), the node agents
# (hy2mgr-node-sync, allinone-agent) and the protocol servers. Settings, users and
# certificates are kept.
set -euo pipefail

REPO="${AIO_REPO:-Jackchen0514/all-in-one}"
BRANCH="${AIO_BRANCH:-main}"

[ "$(id -u)" = 0 ] || { echo "please run as root" >&2; exit 1; }
for c in curl tar; do
  command -v "$c" >/dev/null || { echo "$c is required" >&2; exit 1; }
done

# Pin to the latest commit so the code and install.sh come from the same version
# (raw.githubusercontent.com can serve a stale copy for a few minutes).
sha="$(curl -fsSL -m 15 -H "Accept: application/vnd.github.sha" \
  "https://api.github.com/repos/$REPO/commits/$BRANCH" 2>/dev/null || true)"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || sha=""

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
url="https://github.com/$REPO/archive/${sha:-refs/heads/$BRANCH}.tar.gz"
echo "==> downloading $REPO ${sha:0:7}"
curl -fsSL "$url" | tar -xz -C "$tmp" --strip-components=1

AIO_SRC_SHA="$sha" bash "$tmp/install.sh" update "$@"
