#!/usr/bin/env bash
# allinone installer: one panel for Hysteria2 / AnyTLS / Shadowsocks nodes.
# Certificates: Let's Encrypt via Cloudflare DNS-01.
#
# One-liner (downloads the code automatically when needed):
#   bash <(curl -fsSL https://raw.githubusercontent.com/Jackchen0514/all-in-one/main/install.sh) all ...
#
#   bash install.sh panel  --domain panel.example.com --cf-token TOKEN --email you@mail.com
#   bash install.sh node   --domain hk.example.com    --cf-token TOKEN --email you@mail.com \
#                          --panel https://panel.example.com --api-token API_TOKEN [--name 香港] \
#                          [--type hysteria2,anytls,ss]
#   bash install.sh all    --domain panel.example.com --node-domain hk.example.com --cf-token TOKEN --email you@mail.com
#   bash install.sh update [--no-hysteria] [--no-anytls] [--no-ss] [--force]   (or: bash <(curl .../update.sh))
#   bash install.sh uninstall panel|node
#
# Missing values are asked interactively. Run with --help for every option.
#
# Migration: `panel` adopts an existing hysteria-manager panel (/opt/hy2mgr) on the same machine;
# `node --type anytls` imports the users of an existing anytls-go server and `node --type ss` the
# ports of an existing ssmanager panel on the same machine before taking them over.
#
# Cloudflare API token permissions: Zone -> Zone -> Read, Zone -> DNS -> Edit
# (My Profile -> API Tokens -> Create Token -> "Edit zone DNS" template, then add Zone:Read).
set -euo pipefail

SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]:-$0}")"   # /dev/fd when run via bash <(curl ...)
SCRIPT_DIR="$(cd "$SCRIPT_DIR" 2>/dev/null && pwd)" || SCRIPT_DIR="$PWD"
PANEL_DIR=/opt/allinone
PANEL_USER=allinone
CERT_DIR=/etc/allinone/certs      # one directory per domain, shared by the panel and anytls
CERT_GROUP=allinone-cert
AGENT_BIN=/usr/local/bin/allinone-agent
AGENT_CONF=/etc/allinone/agent.json
HY_BIN=/usr/local/bin/hysteria
HY_CONF_DIR=/etc/hysteria
HY_DATA_DIR=/var/lib/hysteria
HY_USER=hysteria
AT_BIN=/usr/local/bin/anytls-server
AT_CONF_DIR=/etc/anytls            # same paths as anytls-go's own installer, so it can be adopted
AT_DATA_DIR=/var/lib/anytls
AT_USER=anytls
AT_API=127.0.0.1:8843
AT_REPO="${AIO_ANYTLS_REPO:-Jackchen0514/anytls-go}"
SS_BIN_DIR=/usr/local/bin
SS_USER=ssmanager
SS_MANAGER=127.0.0.1:6100
SS_REPO="${AIO_SSRUST_REPO:-Jackchen0514/shadowsocks-rust}"
OLD_HY2MGR_DIR=/opt/hy2mgr
OLD_SSMANAGER_DIR="${AIO_OLD_SSMANAGER_DIR:-/opt/ssmanager}"
ACME_HOME="${HOME:-/root}/.acme.sh"
CF_API="${CF_API:-https://api.cloudflare.com/client/v4}"
REPO="${AIO_REPO:-Jackchen0514/all-in-one}"
BRANCH="${AIO_BRANCH:-main}"

# ---- options ---------------------------------------------------------------
MODE="${1:-}"; [ $# -gt 0 ] && shift
UNINSTALL_WHAT=""
if [ "$MODE" = uninstall ]; then UNINSTALL_WHAT="${1:-}"; [ $# -gt 0 ] && shift; fi
DOMAIN=""; NODE_DOMAIN=""; CF_TOKEN="${CF_TOKEN:-}"; EMAIL=""
PANEL_PORT=443; NODE_PORT=443; ADMIN_USER="admin"; ADMIN_PASS=""
PANEL_URL=""; API_TOKEN=""; NODE_NAME=""; OBFS=""; STATS_PORT=9999; PORT_SET=0; HOP=""; HOP_SET=0
TYPES="hysteria2,anytls,ss"; AT_PORT=""; SS_METHOD=""
HY_VERSION=latest; AT_VERSION=latest; DNS_RECORD=1; UPDATE_HY=1; UPDATE_AT=1; UPDATE_SS=1; FORCE=0

usage() { cat <<'EOF'
Usage:
  install.sh panel  --domain panel.example.com --cf-token TOKEN --email you@mail.com
  install.sh node   --domain hk.example.com --cf-token TOKEN --email you@mail.com \
                    --panel https://panel.example.com --api-token API_TOKEN [--name 香港] [--type ...]
  install.sh all    --domain panel.example.com --node-domain hk.example.com --cf-token TOKEN --email you@mail.com
  install.sh update [--no-hysteria] [--no-anytls] [--no-ss] [--force] [--hy-version V]
  install.sh uninstall panel|node

Cloudflare API token permissions: Zone -> Zone -> Read, Zone -> DNS -> Edit

Options:
  --domain D          panel: panel domain;  node: node domain
  --node-domain D     all: node domain (default: same as --domain)
  --cf-token T        Cloudflare API token (or env CF_TOKEN)
  --email E           ACME account email
  --panel-port P      panel HTTPS port (default 443)
  --admin-user U      panel admin user (default admin)
  --admin-pass P      panel admin password (default: random, kept on re-install)
  --panel URL         node: panel URL, e.g. https://panel.example.com
  --api-token T       node: panel API token (AIO_API_TOKEN of the panel)
  --name N            node: display name (default: node domain; the protocol is appended
                      when several types are installed)
  --type LIST         node / all: protocols to install, comma separated:
                      hysteria2,anytls,ss (default: all three)

  hysteria2:
  --port P            UDP port (default 443; on re-install the panel's value is kept)
  --obfs / --no-obfs  enable / disable salamander obfuscation (default: keep the panel's setting)
  --hop RANGE         port hopping, e.g. 20000-30000 ("" disables; default: keep the panel's setting)
  --stats-port P      traffic stats API port (default 9999)
  --hy-version V      hysteria version, e.g. v2.6.1 (default latest)

  anytls:
  --anytls-port P     TCP port (default 443, 8443 when the panel uses TCP 443 on this machine;
                      an adopted anytls-go server keeps its port)
  --anytls-version V  anytls-go release, e.g. v0.0.35 (default latest)

  shadowsocks:
  --ss-method M       aes-256-gcm | aes-128-gcm | chacha20-ietf-poly1305 (default aes-256-gcm,
                      or the most used method of an adopted ssmanager panel)
                      Every user has their own port, assigned by the panel (AIO_SS_PORT_RANGE).

  --no-dns            don't create/update the Cloudflare A record
  --no-hysteria       update: don't upgrade the hysteria binary
  --no-anytls         update: don't upgrade anytls-server
  --no-ss             update: don't upgrade shadowsocks-rust
  --force             update: reinstall the panel code even if already up to date
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2;;
    --node-domain) NODE_DOMAIN="$2"; shift 2;;
    --cf-token) CF_TOKEN="$2"; shift 2;;
    --email) EMAIL="$2"; shift 2;;
    --panel-port) PANEL_PORT="$2"; shift 2;;
    --port) NODE_PORT="$2"; PORT_SET=1; shift 2;;
    --admin-user) ADMIN_USER="$2"; shift 2;;
    --admin-pass) ADMIN_PASS="$2"; shift 2;;
    --panel) PANEL_URL="${2%/}"; shift 2;;
    --api-token) API_TOKEN="$2"; shift 2;;
    --name) NODE_NAME="$2"; shift 2;;
    --type|--types) TYPES="$2"; shift 2;;
    --obfs) OBFS=1; shift;;
    --no-obfs) OBFS=0; shift;;
    --hop) HOP="$2"; HOP_SET=1; shift 2;;
    --stats-port) STATS_PORT="$2"; shift 2;;
    --hy-version) HY_VERSION="$2"; shift 2;;
    --anytls-port) AT_PORT="$2"; shift 2;;
    --anytls-version) AT_VERSION="$2"; shift 2;;
    --ss-method) SS_METHOD="$2"; shift 2;;
    --no-dns) DNS_RECORD=0; shift;;
    --no-hysteria) UPDATE_HY=0; shift;;
    --no-anytls) UPDATE_AT=0; shift;;
    --no-ss) UPDATE_SS=0; shift;;
    --force) FORCE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1"; usage; exit 1;;
  esac
done

# ---- helpers ---------------------------------------------------------------
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_off=$'\e[0m'
info() { echo "${c_grn}==>${c_off} $*"; }
warn() { echo "${c_ylw}WARN:${c_off} $*" >&2; }
die()  { echo "${c_red}ERROR:${c_off} $*" >&2; exit 1; }
ask() {  # ask VAR "prompt" [secret]
  local __v="$1" __p="$2" __s="${3:-}" __a=""
  [ -n "${!__v}" ] && return
  [ -t 0 ] || die "missing value for $__p (non-interactive; pass it as an option)"
  if [ -n "$__s" ]; then read -rsp "$__p: " __a; echo; else read -rp "$__p: " __a; fi
  [ -n "$__a" ] || die "$__p is required"
  printf -v "$__v" '%s' "$__a"
}
rand() { python3 -c 'import secrets,string,sys; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(int(sys.argv[1]))))' "${1:-24}"; }
valid_domain() { [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]; }
json_get() { python3 -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[k]
print(v)' "$@"; }

need_root() { [ "$(id -u)" = 0 ] || die "please run as root"; }

install_pkgs() {
  local missing=()
  for p in "$@"; do command -v "$p" >/dev/null 2>&1 || missing+=("$p"); done
  [ ${#missing[@]} -eq 0 ] && return
  info "installing packages: ${missing[*]}"
  if command -v apt-get >/dev/null; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q "${missing[@]}"
  elif command -v yum >/dev/null; then yum install -y -q "${missing[@]}"
  elif command -v apk >/dev/null; then apk add -q "${missing[@]}"
  else die "cannot install ${missing[*]}: unknown package manager"; fi
}

public_ip() {
  curl -fsS4 -m 10 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' \
    || curl -fsS4 -m 10 https://api.ipify.org
}

# Cloudflare API helper (python for JSON handling). Usage: cf verify | cf zone DOMAIN | cf upsert DOMAIN IP
cf() {
  CF_TOKEN="$CF_TOKEN" CF_API="$CF_API" python3 - "$@" <<'PY'
import json, os, sys, urllib.request, urllib.error
api, tok = os.environ["CF_API"], os.environ["CF_TOKEN"]
def call(method, path, body=None):
    req = urllib.request.Request(api + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            d = json.load(e)
        except Exception:
            d = {"errors": [{"message": "HTTP %d" % e.code}]}
        sys.exit("cloudflare: " + "; ".join(x.get("message", "") for x in d.get("errors", [])))
def zone(domain):
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        r = call("GET", "/zones?name=" + ".".join(labels[i:]))
        if r.get("result"):
            return r["result"][0]["id"]
    sys.exit("cloudflare: no zone found for %s (token lacks Zone:Read, or the domain is not on this account)" % domain)
cmd = sys.argv[1]
if cmd == "verify":
    r = call("GET", "/user/tokens/verify")
    if r.get("result", {}).get("status") != "active":
        sys.exit("cloudflare: token is not active")
elif cmd == "zone":
    print(zone(sys.argv[2]))
elif cmd == "upsert":
    name, ip = sys.argv[2], sys.argv[3]
    zid = zone(name)
    recs = call("GET", "/zones/%s/dns_records?type=A&name=%s" % (zid, name))["result"]
    body = {"type": "A", "name": name, "content": ip, "ttl": 1, "proxied": False}
    if not recs:
        call("POST", "/zones/%s/dns_records" % zid, body)
        print("created A %s -> %s" % (name, ip))
    elif recs[0]["content"] == ip and not recs[0]["proxied"]:
        print("A %s -> %s already set" % (name, ip))
    else:
        call("PUT", "/zones/%s/dns_records/%s" % (zid, recs[0]["id"]), body)
        print("updated A %s: %s%s -> %s (DNS only)" % (name, recs[0]["content"],
              " (proxied)" if recs[0]["proxied"] else "", ip))
PY
}

CF_DONE=""
setup_cloudflare() {  # setup_cloudflare DOMAIN...
  ask CF_TOKEN "Cloudflare API token" secret
  if [ -z "$CF_DONE" ]; then info "verifying Cloudflare token"; cf verify; CF_DONE=1; fi
  if [ "$DNS_RECORD" = 1 ]; then
    local ip; ip="$(public_ip)" || die "cannot detect public IPv4 (use --no-dns and set the record yourself)"
    for d in "$@"; do cf upsert "$d" "$ip"; done
  fi
}

open_port() {  # open_port PORT tcp|udp [from-ip]
  local port="$1" proto="$2" from="${3:-}"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    if [ -n "$from" ]; then ufw allow from "$from" to any port "$port" proto "$proto" >/dev/null
    else ufw allow "$port/$proto" >/dev/null; fi
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    if [ -n "$from" ]; then
      firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$from port port=$port protocol=$proto accept" >/dev/null
    else firewall-cmd --permanent --add-port="$port/$proto" >/dev/null; fi
    firewall-cmd --reload >/dev/null
  fi
}

# tcp_port_user PORT -> "process pid unit" of the listener on TCP PORT (empty if free)
tcp_port_user() {
  command -v ss >/dev/null || return 0
  local line name pid unit=""
  line="$(ss -Hltnp "sport = :$1" 2>/dev/null | head -1)"
  [ -n "$line" ] || return 0
  name="$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')"
  pid="$(echo "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')"
  [ -n "$pid" ] && unit="$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')"
  echo "${name:-?} ${pid:-?} ${unit:--}"
}

# check_tcp_port PORT OWN_UNIT OPTION: die unless TCP PORT is free or already held by OWN_UNIT
# (a re-install), naming the process / systemd unit in the way.
check_tcp_port() {
  local port="$1" own="$2" opt="$3" name pid unit hint=""
  read -r name pid unit <<<"$(tcp_port_user "$port")"
  [ -z "${name:-}" ] || [ "$unit" = "$own" ] && return 0
  if [ "$unit" = hy2mgr.service ]; then
    hint=" This is the old hysteria-manager panel; allinone replaces it (its database is adopted on the first panel install)."
  fi
  local stop="kill $pid"
  case "$unit" in *.service) stop="systemctl disable --now $unit";; esac
  die "TCP $port is already in use by $name (pid $pid, unit $unit).$hint
       Stop it ($stop) and re-run, or choose another port with $opt"
}

# ---- certificates (acme.sh + Cloudflare DNS-01) ----------------------------
ensure_acme() {
  if ! command -v crontab >/dev/null; then   # acme.sh needs cron for auto-renewal
    if command -v apt-get >/dev/null; then install_pkgs cron; else install_pkgs cronie; fi
    systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
  fi
  if [ ! -x "$ACME_HOME/acme.sh" ]; then
    info "installing acme.sh"
    curl -fsSL https://get.acme.sh | sh -s email="$EMAIL" >/dev/null
  fi
}

# issue_cert DOMAIN -> $CERT_DIR/DOMAIN/{fullchain,key}.pem, readable by group $CERT_GROUP.
# acme.sh keeps one install target per domain, so the panel and anytls share these files and the
# renewal hook restarts whichever of them is running.
issue_cert() {
  local d="$1" zid rc=0 dir="$CERT_DIR/$1"
  ensure_acme
  getent group "$CERT_GROUP" >/dev/null || groupadd --system "$CERT_GROUP"
  zid="$(cf zone "$d")"
  info "issuing certificate for $d (DNS-01, Let's Encrypt)"
  CF_Token="$CF_TOKEN" CF_Zone_ID="$zid" "$ACME_HOME/acme.sh" --issue --dns dns_cf -d "$d" \
    --server letsencrypt --keylength ec-256 || rc=$?
  [ $rc -eq 0 ] || [ $rc -eq 2 ] || die "certificate issuance failed for $d (acme.sh exit $rc)"   # 2 = still valid
  mkdir -p "$dir"
  chown root:"$CERT_GROUP" /etc/allinone "$CERT_DIR" "$dir"; chmod 750 "$CERT_DIR" "$dir"; chmod 755 /etc/allinone
  local fix="chown root:$CERT_GROUP $dir/*.pem && chmod 640 $dir/*.pem"
  "$ACME_HOME/acme.sh" --install-cert -d "$d" --ecc \
    --key-file "$dir/key.pem" --fullchain-file "$dir/fullchain.pem" \
    --reloadcmd "$fix; for s in allinone anytls-server; do systemctl try-restart \$s 2>/dev/null; done; true" \
    >/dev/null || true
  eval "$fix"
}

# ---- source code -----------------------------------------------------------
latest_sha() {
  curl -fsSL -m 15 -H "Accept: application/vnd.github.sha" "https://api.github.com/repos/$REPO/commits/$BRANCH" 2>/dev/null
}

# Sets SRC_DIR (contains allinone/ and agent/) and SRC_SHA (commit, may be empty if unknown).
fetch_source() {
  [ -n "$SRC_DIR" ] && return
  if [ -f "$SCRIPT_DIR/allinone/__main__.py" ]; then
    SRC_DIR="$SCRIPT_DIR"
    SRC_SHA="${AIO_SRC_SHA:-$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)}"
    return
  fi
  SRC_SHA="$(latest_sha || true)"
  local url="https://github.com/$REPO/archive/${SRC_SHA:-refs/heads/$BRANCH}.tar.gz"
  info "downloading allinone ${SRC_SHA:0:7}"
  SRC_DIR="$(mktemp -d)"
  curl -fsSL "$url" | tar -xz -C "$SRC_DIR" --strip-components=1 || die "download failed: $url"
  [ -f "$SRC_DIR/allinone/__main__.py" ] || die "downloaded archive does not contain allinone/"
}

copy_panel_code() {
  rm -rf "$PANEL_DIR/allinone"
  cp -r "$SRC_DIR/allinone" "$PANEL_DIR/"
  find "$PANEL_DIR/allinone" -name __pycache__ -prune -exec rm -rf {} +
  if [ -n "$SRC_SHA" ]; then echo "$SRC_SHA" > "$PANEL_DIR/VERSION"; fi
}

write_panel_unit() {
  cat > /etc/systemd/system/allinone.service <<EOF
[Unit]
Description=allinone panel (Hysteria2 / AnyTLS / Shadowsocks)
After=network-online.target
Wants=network-online.target

[Service]
User=$PANEL_USER
Group=$PANEL_USER
SupplementaryGroups=$CERT_GROUP
WorkingDirectory=$PANEL_DIR
EnvironmentFile=$PANEL_DIR/.env
ExecStart=$(command -v python3) -m allinone
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

env_get() { sed -n "s/^$1=//p" "$PANEL_DIR/.env" 2>/dev/null | head -1; }

# wait_panel: health check against the local panel using the values in .env
wait_panel() {
  local url host port tok
  url="$(env_get AIO_PUBLIC_URL)"; port="$(env_get AIO_PORT)"; tok="$(env_get AIO_API_TOKEN)"
  host="$(echo "$url" | sed -E 's#^https?://([^/:]+).*#\1#')"
  for _ in $(seq 1 20); do
    if curl -fsS -m 3 --resolve "$host:$port:127.0.0.1" "$url/api/v1/stats" \
         -H "Authorization: Bearer $tok" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

# ---- panel -----------------------------------------------------------------
install_panel() {
  ask DOMAIN "Panel domain (e.g. panel.example.com)"
  valid_domain "$DOMAIN" || die "invalid domain: $DOMAIN"
  check_tcp_port "$PANEL_PORT" allinone.service --panel-port   # before touching DNS / certificates
  ask EMAIL "ACME email"
  install_pkgs curl python3 openssl tar
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "python >= 3.8 required"
  fetch_source
  setup_cloudflare "$DOMAIN"
  issue_cert "$DOMAIN"

  id "$PANEL_USER" >/dev/null 2>&1 || useradd --system --home-dir "$PANEL_DIR" --shell /usr/sbin/nologin "$PANEL_USER"
  usermod -aG "$CERT_GROUP" "$PANEL_USER"
  mkdir -p "$PANEL_DIR/data"
  copy_panel_code

  # keep existing secrets on re-install; adopt a hysteria-manager panel on first install
  local env="$PANEL_DIR/.env" db="$PANEL_DIR/data/allinone.db" old_pass="" old_tok="" migrated="" ss_range=""
  if [ -f "$env" ]; then
    old_pass="$(env_get AIO_ADMIN_PASS)"; old_tok="$(env_get AIO_API_TOKEN)"; ss_range="$(env_get AIO_SS_PORT_RANGE)"
  elif [ -f "$OLD_HY2MGR_DIR/.env" ]; then
    old_pass="$(sed -n 's/^HY2M_ADMIN_PASS=//p' "$OLD_HY2MGR_DIR/.env")"
    old_tok="$(sed -n 's/^HY2M_API_TOKEN=//p' "$OLD_HY2MGR_DIR/.env")"
  fi
  local old_db="$OLD_HY2MGR_DIR/data/hy2mgr.db"
  if [ ! -f "$db" ] && [ -f "$old_db" ]; then
    info "adopting hysteria-manager database $old_db"
    python3 -c 'import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()' "$old_db" "$db" \
      || die "copying $old_db failed"
    systemctl disable --now hy2mgr >/dev/null 2>&1 || true   # frees the panel port
    migrated="
  已迁移:     hysteria-manager 的用户/节点/管理员密码/API Token（旧面板 hy2mgr 已停用，数据仍保留在 $OLD_HY2MGR_DIR）"
  fi
  ADMIN_PASS="${ADMIN_PASS:-${old_pass:-$(rand 16)}}"
  API_TOKEN="${old_tok:-$(rand 40)}"
  local url="https://$DOMAIN"; [ "$PANEL_PORT" = 443 ] || url="$url:$PANEL_PORT"
  PANEL_URL="$url"
  umask 077
  cat > "$env" <<EOF
AIO_HOST=0.0.0.0
AIO_PORT=$PANEL_PORT
AIO_DB=$db
AIO_ADMIN_USER=$ADMIN_USER
AIO_ADMIN_PASS=$ADMIN_PASS
AIO_API_TOKEN=$API_TOKEN
AIO_PUBLIC_URL=$url
AIO_SYNC_INTERVAL=60
AIO_SS_PORT_RANGE=${ss_range:-40000-49999}
AIO_TLS_CERT=$CERT_DIR/$DOMAIN/fullchain.pem
AIO_TLS_KEY=$CERT_DIR/$DOMAIN/key.pem
EOF
  umask 022
  chown root:"$PANEL_USER" "$env"; chmod 640 "$env"
  chown -R "$PANEL_USER":"$PANEL_USER" "$PANEL_DIR/data"

  write_panel_unit
  systemctl daemon-reload
  systemctl enable allinone >/dev/null 2>&1
  systemctl restart allinone
  open_port "$PANEL_PORT" tcp

  info "waiting for panel"
  wait_panel || die "panel did not start; see: journalctl -u allinone -n 50"
  PANEL_SUMMARY="
  面板地址:   $url
  管理员:     $ADMIN_USER / $ADMIN_PASS
  API Token:  $API_TOKEN
  配置文件:   $PANEL_DIR/.env
  证书:       acme.sh 自动续期 (crontab -l 查看)$migrated"
}

# ---- node: common ----------------------------------------------------------
go_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64;;
    aarch64|arm64) echo arm64;;
    armv7*|armv6*) echo arm;;
    i386|i686) echo 386;;
    s390x) echo s390x;;
    riscv64) echo riscv64;;
    *) die "unsupported arch $(uname -m)";;
  esac
}

# panel_api METHOD PATH [JSON | -]  -> response body on stdout ("-": JSON body read from stdin)
panel_api() {
  local args=(-fsS -m 60 -X "$1" "$PANEL_URL/api/v1$2" -H "Authorization: Bearer $API_TOKEN")
  if [ "${3:-}" = - ]; then args+=(-H "Content-Type: application/json" --data-binary @-)
  elif [ -n "${3:-}" ]; then args+=(-H "Content-Type: application/json" -d "$3"); fi
  [ -n "${PANEL_RESOLVE:-}" ] && args+=(--resolve "$PANEL_RESOLVE")
  curl "${args[@]}"
}

# find_node TYPE -> "id<US>port<US>obfs<US>hop<US>ss_method" of the panel node with this address + type
find_node() {
  panel_api GET /nodes | ADDR="$DOMAIN" TYPE="$1" python3 -c '
import json, os, sys
for n in json.load(sys.stdin)["items"]:
    if n["address"] == os.environ["ADDR"] and n.get("type", "hysteria2") == os.environ["TYPE"]:
        print("\x1f".join(str(n.get(k, "")) for k in ("id", "port", "obfs_password", "hop_ports", "ss_method"))); break'
}

# register_node ID JSON -> node JSON (creates when ID is empty)
register_node() {
  if [ -n "$1" ]; then panel_api PATCH "/nodes/$1" "$2"; else panel_api POST /nodes "$2"; fi
}

node_name() {  # node_name LABEL
  if [ "$(echo "$TYPES" | tr ',' '\n' | grep -c .)" -gt 1 ]; then echo "$NODE_NAME $1"; else echo "$NODE_NAME"; fi
}

install_node() {
  ask DOMAIN "Node domain (e.g. hk.example.com)"
  valid_domain "$DOMAIN" || die "invalid domain: $DOMAIN"
  ask EMAIL "ACME email"
  ask PANEL_URL "Panel URL (e.g. https://panel.example.com)"
  PANEL_URL="${PANEL_URL%/}"
  ask API_TOKEN "Panel API token" secret
  NODE_NAME="${NODE_NAME:-$DOMAIN}"
  TYPES="$(echo "$TYPES" | tr 'A-Z' 'a-z' | sed 's/\bhy2\b/hysteria2/; s/\bshadowsocks\b/ss/g')"
  local t
  for t in $(echo "$TYPES" | tr ',' ' '); do
    case "$t" in hysteria2|anytls|ss) ;; *) die "unknown --type $t (use hysteria2, anytls, ss)";; esac
  done
  install_pkgs curl python3 tar
  setup_cloudflare "$DOMAIN"

  info "checking panel API"
  panel_api GET /stats >/dev/null || die "cannot reach panel API at $PANEL_URL (check URL / API token)"
  fetch_source

  AGENT_NODES=()
  for t in $(echo "$TYPES" | tr ',' ' '); do
    case "$t" in
      hysteria2) install_hysteria_node;;
      anytls) install_anytls_node;;
      ss) install_ss_node;;
    esac
  done
  if [ ${#AGENT_NODES[@]} -gt 0 ]; then install_agent "${AGENT_NODES[@]}"; fi
}

# ---- node: hysteria2 -------------------------------------------------------
install_hysteria_bin() {
  local arch url; arch="$(go_arch)"
  if [ "$HY_VERSION" = latest ]; then
    url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-$arch"
  else
    url="https://github.com/apernet/hysteria/releases/download/app/$HY_VERSION/hysteria-linux-$arch"
  fi
  info "downloading hysteria ($HY_VERSION, $arch)"
  curl -fsSL -o "$HY_BIN.new" "$url" || die "download failed: $url"
  chmod +x "$HY_BIN.new"
  "$HY_BIN.new" version >/dev/null || die "downloaded hysteria binary does not run"
  mv -f "$HY_BIN.new" "$HY_BIN"
}

install_hysteria_node() {
  info "[hysteria2] installing"
  command -v iptables >/dev/null || install_pkgs iptables || warn "iptables not available: port hopping will not work"
  install_hysteria_bin
  id "$HY_USER" >/dev/null 2>&1 || useradd --system --home-dir "$HY_DATA_DIR" --shell /usr/sbin/nologin "$HY_USER"
  mkdir -p "$HY_CONF_DIR" "$HY_DATA_DIR/acme"
  chown -R "$HY_USER":"$HY_USER" "$HY_DATA_DIR"

  # keep stats secret on re-install
  local conf="$HY_CONF_DIR/config.yaml" secret="" obfs_pw="" port_spec="$NODE_PORT" hop="$HOP"
  if [ -f "$conf" ]; then secret="$(sed -n 's/^  secret: //p' "$conf" | head -1)"; fi
  secret="${secret:-$(rand 32)}"

  # An already registered node keeps the port / obfs set in the panel unless overridden here.
  local existing="" cur_port="" cur_obfs="" cur_hop=""
  IFS=$'\x1f' read -r existing cur_port cur_obfs cur_hop _ < <(find_node hysteria2) || true
  if [ -n "$existing" ]; then
    [ "$PORT_SET" = 1 ] || port_spec="$cur_port"
    [ "$OBFS" = 0 ] || obfs_pw="$cur_obfs"
    [ "$HOP_SET" = 1 ] || hop="$cur_hop"
  fi
  if [ "$OBFS" = 1 ] && [ -z "$obfs_pw" ]; then obfs_pw="$(rand 24)"; fi
  local listen_port="${port_spec%%[-,]*}"   # hysteria listens on the first port of a range / list

  # Same machine as the panel -> stats API stays on localhost.
  local stats_listen stats_url local_panel=0
  if [ "$MODE" = all ]; then
    local_panel=1
    stats_listen="127.0.0.1:$STATS_PORT"; stats_url="http://127.0.0.1:$STATS_PORT"
  else
    stats_listen=":$STATS_PORT"; stats_url="http://$DOMAIN:$STATS_PORT"
  fi

  info "[hysteria2] registering node on panel"
  local body node_json
  body="$(NAME="$(node_name HY2)" ADDR="$DOMAIN" PORT="$port_spec" OBFS="$obfs_pw" HOP="$hop" URL="$stats_url" SEC="$secret" python3 -c '
import json, os
print(json.dumps({"type": "hysteria2", "name": os.environ["NAME"], "address": os.environ["ADDR"],
                  "port": os.environ["PORT"], "sni": os.environ["ADDR"], "insecure": False,
                  "obfs_password": os.environ["OBFS"], "hop_ports": os.environ["HOP"],
                  "api_url": os.environ["URL"], "api_secret": os.environ["SEC"], "enabled": True}))')"
  node_json="$(register_node "$existing" "$body")" || die "panel rejected the hysteria2 node settings (check --port / --hop)"
  local auth_token; auth_token="$(echo "$node_json" | json_get auth_token)"

  info "[hysteria2] writing $conf"
  umask 027
  {
    echo "listen: :$listen_port"
    echo
    echo "acme:"
    echo "  domains:"
    echo "    - $DOMAIN"
    echo "  email: $EMAIL"
    echo "  ca: letsencrypt"
    echo "  dir: $HY_DATA_DIR/acme"
    echo "  type: dns"
    echo "  dns:"
    echo "    name: cloudflare"
    echo "    config:"
    echo "      cloudflare_api_token: $CF_TOKEN"
    echo
    if [ -n "$obfs_pw" ]; then
      echo "obfs:"
      echo "  type: salamander"
      echo "  salamander:"
      echo "    password: $(V="$obfs_pw" python3 -c 'import json,os; print(json.dumps(os.environ["V"]))')"
      echo
    fi
    echo "auth:"
    echo "  type: http"
    echo "  http:"
    echo "    url: $PANEL_URL/hy2/auth/$auth_token"
    echo "    insecure: false"
    echo
    echo "trafficStats:"
    echo "  listen: $stats_listen"
    echo "  secret: $secret"
    echo
    echo "masquerade:"
    echo "  type: proxy"
    echo "  proxy:"
    echo "    url: https://www.bing.com/"
    echo "    rewriteHost: true"
  } > "$conf"
  umask 022
  chown root:"$HY_USER" "$conf"; chmod 640 "$conf"

  # bigger UDP buffers for QUIC
  cat > /etc/sysctl.d/99-hysteria.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
  sysctl -q -p /etc/sysctl.d/99-hysteria.conf || true

  write_hysteria_unit
  install_hy2_sync_agent
  systemctl daemon-reload
  systemctl enable hysteria-server >/dev/null 2>&1
  local started; started="$(date +%s)"
  systemctl restart hysteria-server
  systemctl enable --now hy2mgr-node-sync.timer >/dev/null 2>&1

  open_port "$listen_port" udp
  if [ $local_panel = 0 ]; then
    local panel_host panel_ip
    panel_host="$(echo "$PANEL_URL" | sed -E 's#^https?://([^/:]+).*#\1#')"
    panel_ip="$(getent ahostsv4 "$panel_host" | awk 'NR==1{print $1}')"
    if [ -n "$panel_ip" ]; then open_port "$STATS_PORT" tcp "$panel_ip"; fi
  fi

  info "[hysteria2] waiting for hysteria to obtain the certificate (DNS-01 can take ~1 min)"
  if ! wait_hysteria "$started"; then
    journalctl -u hysteria-server -n 20 --no-pager || true
    die "hysteria did not start; see: journalctl -u hysteria-server -n 50"
  fi

  # apply port hopping rules (and report the state to the panel) right away
  systemctl start hy2mgr-node-sync >/dev/null 2>&1 || warn "hy2mgr-node-sync failed; see: journalctl -u hy2mgr-node-sync"

  info "[hysteria2] testing panel -> node stats API"
  local node_id; node_id="$(echo "$node_json" | json_get id)"
  if ! panel_api POST "/nodes/$node_id/sync" >/dev/null 2>&1; then
    if [ $local_panel = 1 ]; then
      warn "panel cannot reach $stats_url yet; check: journalctl -u hysteria-server -n 50"
    else
      warn "panel cannot reach $stats_url yet. Allow TCP $STATS_PORT from the panel server in your firewall / security group."
    fi
  fi

  NODE_SUMMARY="$NODE_SUMMARY
  Hysteria2:  $DOMAIN:$listen_port/udp${hop:+，端口跳跃 $hop}  配置 $conf
              统计 API $stats_url（仅需对面板开放），日志 journalctl -u hysteria-server -f"
  if [ $local_panel = 0 ]; then
    FIREWALL_HINT="$FIREWALL_HINT UDP $listen_port${hop:+、UDP $hop}、来自面板的 TCP $STATS_PORT;"
  fi
}

write_hysteria_unit() {
  cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network-online.target
Wants=network-online.target

[Service]
User=$HY_USER
Group=$HY_USER
WorkingDirectory=$HY_DATA_DIR
Environment=HYSTERIA_LOG_LEVEL=info
ExecStart=$HY_BIN server -c $HY_CONF_DIR/config.yaml
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
LimitNOFILE=1048576
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

# wait_hysteria SINCE_EPOCH: wait until hysteria logs "server up and running" after SINCE_EPOCH
wait_hysteria() {
  for _ in $(seq 1 90); do
    systemctl is-active -q hysteria-server || return 1
    if journalctl -u hysteria-server --since "@$1" --no-pager 2>/dev/null | grep -q "server up and running"; then return 0; fi
    sleep 2
  done
  return 1
}

latest_hysteria_version() {
  curl -fsSLI -m 20 -o /dev/null -w '%{url_effective}' https://github.com/apernet/hysteria/releases/latest 2>/dev/null \
    | sed -n 's#.*/tag/app/\(v[0-9][0-9.]*\)$#\1#p'
}

# Agent that pulls port / obfs settings from the panel and applies them to config.yaml.
install_hy2_sync_agent() {
  cat > /usr/local/bin/hy2mgr-node-sync <<'AGENT'
#!/usr/bin/env python3
"""Pull this node's port / obfs / port-hopping settings from the panel and apply
them: port and obfs go into the hysteria config (rolled back if hysteria fails to start),
port hopping is an iptables REDIRECT of a UDP port range to the listen port. Runs every
minute, so the NAT rules are restored after a reboot."""
import json, os, re, shutil, subprocess, sys, time, urllib.parse, urllib.request

CONF = os.environ.get("HY_CONF", "/etc/hysteria/config.yaml")
SERVICE = "hysteria-server"
# Settings that failed to start are remembered so we don't restart-loop every minute.
FAILED = os.environ.get("HY_SYNC_FAILED", "/run/hy2mgr-node-sync.failed")
CHAIN = "HY2MGR_HOP"
OBFS_RE = re.compile(r"^obfs:\n(?:[ \t]+.*\n)*\n?", re.M)


def current(text):
    m = re.search(r"^listen:\s*\S*?:?(\d+)\s*$", text, re.M)
    port = m.group(1) if m else ""
    obfs = ""
    b = OBFS_RE.search(text)
    if b:
        pm = re.search(r"^\s+password:\s*(.+?)\s*$", b.group(0), re.M)
        if pm:
            v = pm.group(1)
            obfs = json.loads(v) if v.startswith('"') else v.strip("'")
    return port, obfs


def fetch(base, token, port, obfs, hop):
    q = urllib.parse.urlencode({"port": port, "obfs": obfs, "hop": hop})
    with urllib.request.urlopen("%s/hy2/node/%s/config?%s" % (base, token, q), timeout=15) as r:
        return json.load(r)


def open_firewall(port):
    def ok(cmd):
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if shutil.which("ufw") and b"Status: active" in subprocess.run(["ufw", "status"], stdout=subprocess.PIPE).stdout:
        ok(["ufw", "allow", "%s/udp" % port])
    elif shutil.which("firewall-cmd") and ok(["firewall-cmd", "--state"]):
        ok(["firewall-cmd", "--permanent", "--add-port=%s/udp" % port]) and ok(["firewall-cmd", "--reload"])


def ipt(tool, *args):
    return subprocess.run([tool, "-w", "-t", "nat"] + list(args), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)


def hop_rules_ok(listen, spec):
    """True if the IPv4 NAT chain already redirects exactly `spec` to `listen`."""
    r = ipt("iptables", "-S", CHAIN)
    rules = r.stdout.decode() if r.returncode == 0 else ""
    if not spec:
        return "-A " not in rules
    sig = "hy2mgr:%s:%s" % (listen, spec)
    return re.search(re.escape(sig) + r'(?=["\s]|$)', rules) is not None and \
        ipt("iptables", "-C", "PREROUTING", "-j", CHAIN).returncode == 0


def ensure_hop(listen, spec):
    """Redirect UDP ports in `spec` (e.g. 20000-30000,40000-41000) to `listen`.
    Returns the spec now in effect ("" if disabled or not applicable)."""
    if not shutil.which("iptables"):
        if spec:
            print("iptables not found, port hopping not applied", file=sys.stderr)
        return ""
    if hop_rules_ok(listen, spec):
        return spec
    sig = "hy2mgr:%s:%s" % (listen, spec)
    for tool in ("iptables", "ip6tables"):
        if not shutil.which(tool):
            continue
        ipt(tool, "-N", CHAIN)
        ipt(tool, "-F", CHAIN)
        errs = []
        for part in spec.split(",") if spec else []:
            r = ipt(tool, "-A", CHAIN, "-p", "udp", "--dport", part.replace("-", ":"),
                    "-m", "comment", "--comment", sig, "-j", "REDIRECT", "--to-ports", str(listen))
            if r.returncode:
                errs.append(r.stderr.decode().strip())
        if spec and ipt(tool, "-C", "PREROUTING", "-j", CHAIN).returncode:
            r = ipt(tool, "-I", "PREROUTING", "-j", CHAIN)
            if r.returncode:
                errs.append(r.stderr.decode().strip())
        if errs and tool == "iptables":  # IPv6 NAT is best effort
            ipt(tool, "-F", CHAIN)
            print("port hopping rules failed: %s" % "; ".join(errs), file=sys.stderr)
            return ""
    print("port hopping: udp %s -> %s" % (spec, listen) if spec else "port hopping disabled")
    return spec


def write(text, ref):
    st = os.stat(ref)
    tmp = ref + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, ref)


def restart_ok():
    subprocess.run(["systemctl", "restart", SERVICE])
    time.sleep(5)
    return subprocess.run(["systemctl", "is-active", "-q", SERVICE]).returncode == 0


def main():
    text = open(CONF).read()
    m = re.search(r"^\s+url:\s*(\S+)/hy2/auth/(\S+?)\s*$", text, re.M)
    if not m:
        sys.exit("panel auth url not found in " + CONF)
    base, token = m.group(1), m.group(2)
    port, obfs = current(text)
    hop = spec_if_ok(port)
    before = (port, obfs, hop)
    want = fetch(base, token, port, obfs, hop)
    new_port, new_obfs = str(want["listen_port"]), want.get("obfs_password") or ""
    new_hop = want.get("hop_ports") or ""
    error = None

    if (new_port, new_obfs) != (port, obfs) and not failed_before(new_port, new_obfs):
        new = re.sub(r"^listen:.*$", "listen: :" + new_port, text, count=1, flags=re.M)
        new = OBFS_RE.sub("", new)
        if new_obfs:
            block = "obfs:\n  type: salamander\n  salamander:\n    password: %s\n\n" % json.dumps(new_obfs)
            new = re.sub(r"^auth:", lambda _: block + "auth:", new, count=1, flags=re.M)
        write(new, CONF)
        if new_port != port:
            open_firewall(new_port)
        if restart_ok():
            print("applied: port %s -> %s, obfs %s" % (port, new_port, "on" if new_obfs else "off"))
            port, obfs = new_port, new_obfs
        else:
            write(text, CONF)
            restart_ok()
            with open(FAILED, "w") as f:
                json.dump([new_port, new_obfs], f)
            error = ("hysteria failed to start with the new settings (port %s); rolled back, "
                     "fix them in the panel (see journalctl -u %s)" % (new_port, SERVICE))

    # Port hopping always targets the listen port actually in use.
    applied_hop = ensure_hop(port, new_hop)
    if (port, obfs, applied_hop) != before:
        fetch(base, token, port, obfs, applied_hop)  # report the applied state
    if error:
        sys.exit(error)


def spec_if_ok(port):
    """The hop spec currently in effect for `port`, read back from the NAT chain."""
    if not shutil.which("iptables"):
        return ""
    r = ipt("iptables", "-S", CHAIN)
    m = re.search(r"hy2mgr:%s:([0-9,-]+)" % re.escape(port), r.stdout.decode() if r.returncode == 0 else "")
    return m.group(1) if m and hop_rules_ok(port, m.group(1)) else ""


def failed_before(new_port, new_obfs):
    try:
        with open(FAILED) as f:
            return json.load(f) == [new_port, new_obfs]
    except (OSError, ValueError):
        return False


if __name__ == "__main__":
    main()
AGENT
  chmod 755 /usr/local/bin/hy2mgr-node-sync

  cat > /etc/systemd/system/hy2mgr-node-sync.service <<'EOF'
[Unit]
Description=Apply allinone panel node settings to hysteria
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hy2mgr-node-sync
EOF
  cat > /etc/systemd/system/hy2mgr-node-sync.timer <<'EOF'
[Unit]
Description=Poll allinone panel for hysteria node settings

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
}

# ---- node: anytls ----------------------------------------------------------
# install_anytls_bin [VERSION] -> installs anytls-server from the anytls-go GitHub release (SHA256SUMS verified)
# shellcheck disable=SC2120  # VERSION is passed by upgrade_core
install_anytls_bin() {
  local ver="${1:-$AT_VERSION}" arch base tmp asset
  arch="$(go_arch)"
  case "$arch" in amd64|arm64) ;; *) die "anytls-go only ships amd64 / arm64 builds (this is $(uname -m))";; esac
  if [ "$ver" = latest ]; then base="https://github.com/$AT_REPO/releases/latest/download"
  else base="https://github.com/$AT_REPO/releases/download/$ver"; fi
  asset="anytls-linux-$arch.tar.gz"
  tmp="$(mktemp -d)"
  info "downloading anytls-server ($ver, $arch)"
  curl -fsSL -o "$tmp/$asset" "$base/$asset" || die "download failed: $base/$asset"
  curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "download failed: $base/SHA256SUMS"
  (cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "checksum mismatch for $asset"
  tar -xzf "$tmp/$asset" -C "$tmp"
  install -m 755 "$tmp/anytls-server" "$AT_BIN"
  rm -rf "$tmp"
}

latest_anytls_version() {
  curl -fsSLI -m 20 -o /dev/null -w '%{url_effective}' "https://github.com/$AT_REPO/releases/latest" 2>/dev/null \
    | sed -n 's#.*/tag/\(v[0-9][0-9.]*\)$#\1#p'
}

# unit_flag UNIT FLAG -> value of `FLAG value` in the ExecStart of a systemd unit
unit_flag() {
  sed -n 's/^ExecStart=//p' "$1" 2>/dev/null | tr ' ' '\n' | awk -v f="$2" 'p{print; exit} $0==f{p=1}'
}

install_anytls_node() {
  info "[anytls] installing"
  local unit=/etc/systemd/system/anytls-server.service cred="$AT_CONF_DIR/credentials.env"
  local boot_pw="" api_key="" old_listen="" old_fallback="" adopted=""
  # an anytls-go installed by its own install.sh (or by us before) is adopted: same paths
  if [ -f "$cred" ]; then
    boot_pw="$(sed -n 's/^PREV_PASSWORD=//p' "$cred")"; api_key="$(sed -n 's/^PREV_API_KEY=//p' "$cred")"
  fi
  if [ -f "$unit" ]; then
    old_listen="$(unit_flag "$unit" -l)"; old_fallback="$(unit_flag "$unit" -fallback)"
  fi
  if [ -z "$AT_PORT" ]; then
    if [ -n "$old_listen" ]; then AT_PORT="${old_listen##*:}"
    elif [ "$MODE" = all ] && [ "$PANEL_PORT" = 443 ]; then AT_PORT=8443
    else AT_PORT=443; fi
  fi
  check_tcp_port "$AT_PORT" anytls-server.service --anytls-port

  # import users of a running standalone anytls-go before the agent takes over
  local existing=""
  IFS=$'\x1f' read -r existing _ < <(find_node anytls) || true
  if [ -z "$existing" ] && [ -n "$api_key" ] && systemctl is-active -q anytls-server 2>/dev/null; then
    local api; api="$(unit_flag "$unit" -api-listen)"; api="${api:-$AT_API}"
    local users=""
    users="$(curl -fsSk -m 10 -H "Authorization: Bearer $api_key" "https://$api/api/users" 2>/dev/null \
          || curl -fsS -m 10 -H "Authorization: Bearer $api_key" "http://$api/api/users" 2>/dev/null || true)"
    if [ -n "$users" ] && [ "$users" != "[]" ]; then
      info "[anytls] importing users of the existing anytls-go server into the panel"
      local res
      res="$(echo "$users" | python3 -c 'import json,sys; print(json.dumps({"source":"anytls","items":json.load(sys.stdin)}))' \
            | panel_api POST /import -)" || die "importing anytls users into the panel failed"
      adopted="$(echo "$res" | python3 -c 'import json,sys; r=json.load(sys.stdin)
print("导入 %d 个用户%s" % (len(r["created"]), "，跳过 %d 个: %s" % (len(r["skipped"]), ", ".join("%s(%s)" % (x["item"], x["reason"]) for x in r["skipped"])) if r["skipped"] else ""))')"
      info "[anytls] $adopted"
    fi
  fi

  issue_cert "$DOMAIN"
  if [ "$AT_VERSION" = latest ]; then AT_VERSION="$(latest_anytls_version)"; AT_VERSION="${AT_VERSION:-latest}"; fi
  install_anytls_bin
  id "$AT_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$AT_USER"
  usermod -aG "$CERT_GROUP" "$AT_USER"
  mkdir -p "$AT_DATA_DIR" "$AT_CONF_DIR"
  chown -R "$AT_USER":"$AT_USER" "$AT_DATA_DIR"
  boot_pw="${boot_pw:-$(rand 32)}"; api_key="${api_key:-$(rand 32)}"
  umask 077
  printf '# generated by install.sh, keep this file secret\nPREV_PASSWORD=%s\nPREV_API_KEY=%s\n' "$boot_pw" "$api_key" > "$cred"
  umask 022

  info "[anytls] registering node on panel"
  local body node_json
  body="$(NAME="$(node_name AnyTLS)" ADDR="$DOMAIN" PORT="$AT_PORT" python3 -c '
import json, os
print(json.dumps({"type": "anytls", "name": os.environ["NAME"], "address": os.environ["ADDR"],
                  "port": os.environ["PORT"], "sni": os.environ["ADDR"], "insecure": False, "enabled": True}))')"
  node_json="$(register_node "$existing" "$body")" || die "panel rejected the anytls node settings"

  # -p only bootstraps a user when the database is empty (the agent deletes it on its first run)
  local cmd="$AT_BIN -l 0.0.0.0:$AT_PORT -p $boot_pw -db $AT_DATA_DIR/anytls.db -api-listen $AT_API -api-key $api_key"
  cmd="$cmd -cert $CERT_DIR/$DOMAIN/fullchain.pem -key $CERT_DIR/$DOMAIN/key.pem"
  if [ -n "$old_fallback" ]; then cmd="$cmd -fallback $old_fallback"; fi
  cat > "$unit" <<EOF
[Unit]
Description=AnyTLS Server (managed by allinone-agent)
After=network.target

[Service]
Type=simple
User=$AT_USER
Group=$AT_USER
SupplementaryGroups=$CERT_GROUP
ExecStart=$cmd
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$AT_DATA_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable anytls-server >/dev/null 2>&1
  systemctl restart anytls-server
  sleep 3
  systemctl is-active -q anytls-server || { journalctl -u anytls-server -n 20 --no-pager || true; die "anytls-server did not start"; }
  open_port "$AT_PORT" tcp
  echo "$AT_VERSION" > "$AT_CONF_DIR/allinone.version"

  AGENT_NODES+=("$(TOKEN="$(echo "$node_json" | json_get auth_token)" KEY="$api_key" API="https://$AT_API" python3 -c '
import json, os
print(json.dumps({"token": os.environ["TOKEN"], "type": "anytls", "api": os.environ["API"], "api_key": os.environ["KEY"]}))')")
  NODE_SUMMARY="$NODE_SUMMARY
  AnyTLS:     $DOMAIN:$AT_PORT/tcp  管理 API $AT_API (仅本机)，日志 journalctl -u anytls-server -f${adopted:+
              已接管原 anytls-go：$adopted}"
  [ "$MODE" = all ] || FIREWALL_HINT="$FIREWALL_HINT TCP $AT_PORT;"
}

# ---- node: shadowsocks -----------------------------------------------------
# install_ssrust_bin -> sets SS_TAG; installs ssmanager / ssserver from the shadowsocks-rust release
install_ssrust_bin() {
  local target tmp asset url
  case "$(uname -m)" in   # musl: no dependency on the host glibc version
    x86_64) target="x86_64-unknown-linux-musl";;
    aarch64|arm64) target="aarch64-unknown-linux-musl";;
    armv7l) target="armv7-unknown-linux-musleabihf";;
    *) die "unsupported architecture for shadowsocks-rust: $(uname -m)";;
  esac
  SS_TAG="$(curl -fsSLI -m 20 -o /dev/null -w '%{url_effective}' "https://github.com/$SS_REPO/releases/latest" 2>/dev/null \
            | sed -n 's#.*/tag/\(v[0-9][0-9.]*\)$#\1#p')"
  [ -n "$SS_TAG" ] || die "cannot determine the latest shadowsocks-rust release of $SS_REPO"
  asset="shadowsocks-$SS_TAG.$target.tar.xz"
  url="https://github.com/$SS_REPO/releases/download/$SS_TAG/$asset"
  tmp="$(mktemp -d)"
  info "downloading shadowsocks-rust $SS_TAG ($target)"
  curl -fsSL -o "$tmp/$asset" "$url" || die "download failed: $url"
  curl -fsSL -o "$tmp/$asset.sha256" "$url.sha256" || die "download failed: $url.sha256"
  (cd "$tmp" && sha256sum -c "$asset.sha256" >/dev/null) || die "checksum mismatch for $asset"
  tar -xf "$tmp/$asset" -C "$tmp"
  for b in ssmanager ssserver; do install -m 755 "$tmp/$b" "$SS_BIN_DIR/$b"; done
  rm -rf "$tmp"
}

write_ssmanager_unit() {  # write_ssmanager_unit EXTRA_ARGS
  cat > /etc/systemd/system/ssmanager.service <<EOF
[Unit]
Description=shadowsocks-rust ssmanager (ports managed by allinone-agent)
After=network-online.target
Wants=network-online.target

[Service]
User=$SS_USER
Group=$SS_USER
ExecStart=$SS_BIN_DIR/ssmanager --manager-addr $SS_MANAGER -s 0.0.0.0 $1
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

install_ss_node() {
  info "[shadowsocks] installing"
  local existing="" cur_method="" adopted="" import_method=""
  IFS=$'\x1f' read -r existing _ _ _ cur_method < <(find_node shadowsocks) || true

  # import the ports of a standalone ssmanager panel on this machine, then retire it
  local old_db="$OLD_SSMANAGER_DIR/backend/data/ssmanager.db"
  if [ -f "$old_db" ] && [ -f /etc/systemd/system/ssmanager-panel.service ]; then
    info "[shadowsocks] importing ports of the existing ssmanager panel ($old_db)"
    local res
    res="$(python3 - "$old_db" <<'PY' | panel_api POST /import -
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1]); db.row_factory = sqlite3.Row
mult = 1.0
try:
    mult = db.execute("SELECT traffic_multiplier FROM manager_config WHERE id=1").fetchone()[0] or 1.0
except sqlite3.Error:
    pass
items = [dict(r, traffic_multiplier=mult) for r in db.execute("SELECT * FROM ports")]
print(json.dumps({"source": "ssmanager", "items": items}))
PY
)" || die "importing ssmanager ports into the panel failed"
    adopted="$(echo "$res" | python3 -c 'import json,sys; r=json.load(sys.stdin)
print("导入 %d 个端口%s" % (len(r["created"]), "，跳过 %d 个: %s" % (len(r["skipped"]), ", ".join("%s(%s)" % (x["item"], x["reason"]) for x in r["skipped"])) if r["skipped"] else ""))')"
    import_method="$(echo "$res" | python3 -c 'import json,sys; m=json.load(sys.stdin).get("methods") or {}
print(max(m, key=m.get) if m else "")')"
    if [ "$(echo "$res" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("methods") or {}))')" -gt 1 ]; then
      warn "the imported ports use several ciphers; the node uses one ($import_method) for every user"
    fi
    info "[shadowsocks] $adopted; stopping ssmanager-panel"
    systemctl disable --now ssmanager-panel >/dev/null 2>&1 || true
  fi
  local method="${SS_METHOD:-${import_method:-${cur_method:-aes-256-gcm}}}"

  install_ssrust_bin
  id "$SS_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SS_USER"

  info "[shadowsocks] registering node on panel"
  local body node_json
  body="$(NAME="$(node_name SS)" ADDR="$DOMAIN" METHOD="$method" python3 -c '
import json, os
print(json.dumps({"type": "shadowsocks", "name": os.environ["NAME"], "address": os.environ["ADDR"],
                  "ss_method": os.environ["METHOD"], "enabled": True}))')"
  node_json="$(register_node "$existing" "$body")" || die "panel rejected the shadowsocks node settings (check --ss-method)"

  # -U: TCP and UDP. Fall back to TCP-only flags if this ssmanager build doesn't accept it.
  write_ssmanager_unit "-U"
  systemctl daemon-reload
  systemctl enable ssmanager >/dev/null 2>&1
  systemctl restart ssmanager
  sleep 3
  if ! systemctl is-active -q ssmanager; then
    warn "ssmanager -U failed to start, retrying without it (UDP may be disabled)"
    write_ssmanager_unit ""
    systemctl daemon-reload; systemctl restart ssmanager; sleep 3
    systemctl is-active -q ssmanager || { journalctl -u ssmanager -n 20 --no-pager || true; die "ssmanager did not start"; }
  fi
  echo "$SS_TAG" > /etc/allinone/ssrust.version

  local range; range="$(panel_api GET /settings | json_get ss_port_range 2>/dev/null || echo 40000-49999)"
  AGENT_NODES+=("$(TOKEN="$(echo "$node_json" | json_get auth_token)" MGR="$SS_MANAGER" python3 -c '
import json, os
print(json.dumps({"token": os.environ["TOKEN"], "type": "shadowsocks", "manager": os.environ["MGR"]}))')")
  NODE_SUMMARY="$NODE_SUMMARY
  Shadowsocks: $DOMAIN ($method)，每个用户一个端口 (面板范围 $range)，日志 journalctl -u ssmanager -f${adopted:+
              已接管原 ssmanager 面板：$adopted}"
  FIREWALL_HINT="$FIREWALL_HINT TCP+UDP $range（以及导入的旧端口）;"
}

# ---- allinone-agent --------------------------------------------------------
install_agent_bin() {
  install -m 755 "$SRC_DIR/agent/allinone_agent.py" "$AGENT_BIN"
  cat > /etc/systemd/system/allinone-agent.service <<EOF
[Unit]
Description=allinone node agent (anytls / shadowsocks)
After=network-online.target anytls-server.service ssmanager.service
Wants=network-online.target

[Service]
ExecStart=$(command -v python3) $AGENT_BIN --config $AGENT_CONF
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

# install_agent NODE_JSON... -> merge the nodes into $AGENT_CONF (one entry per type) and start the agent
install_agent() {
  info "installing allinone-agent"
  install_agent_bin
  mkdir -p /etc/allinone
  umask 077
  PANEL="$PANEL_URL" python3 - "$AGENT_CONF" "$@" <<'PY'
import json, os, sys
path, new = sys.argv[1], [json.loads(x) for x in sys.argv[2:]]
try:
    cfg = json.load(open(path))
except (OSError, ValueError):
    cfg = {}
types = {n["type"] for n in new}
cfg["panel"] = os.environ["PANEL"]
cfg.setdefault("interval", 30)
cfg["nodes"] = [n for n in cfg.get("nodes", []) if n.get("type") not in types] + new
with open(path + ".tmp", "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
os.replace(path + ".tmp", path)
PY
  umask 022
  chmod 600 "$AGENT_CONF"
  systemctl daemon-reload
  systemctl enable allinone-agent >/dev/null 2>&1
  # one cycle in the foreground so problems show up right here, then the service takes over
  python3 "$AGENT_BIN" --config "$AGENT_CONF" --once || warn "first agent cycle reported errors (see above)"
  systemctl restart allinone-agent
}

# ---- update ----------------------------------------------------------------
update_panel() {
  local cur; cur="$(cat "$PANEL_DIR/VERSION" 2>/dev/null || true)"
  if [ -n "$SRC_SHA" ] && [ "$cur" = "$SRC_SHA" ] && [ "$FORCE" != 1 ]; then
    info "panel is up to date (${SRC_SHA:0:7})"
    UPDATE_SUMMARY="$UPDATE_SUMMARY
  面板:       已是最新 ${SRC_SHA:0:7}"
    return
  fi
  info "updating panel ${cur:0:7} -> ${SRC_SHA:-latest}"

  # online backup of the database (safe while the panel is running)
  local db bak_dir bak
  db="$(env_get AIO_DB)"; db="${db:-$PANEL_DIR/data/allinone.db}"
  bak_dir="$PANEL_DIR/data/backups"; bak="$bak_dir/allinone-$(date +%Y%m%d-%H%M%S).db"
  if [ -f "$db" ]; then
    mkdir -p "$bak_dir"
    python3 -c 'import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()' "$db" "$bak" \
      || die "database backup failed"
    chown -R "$PANEL_USER":"$PANEL_USER" "$bak_dir"
    # keep the 10 newest backups
    find "$bak_dir" -name 'allinone-*.db' | sort -r | tail -n +11 | xargs -r rm -f
    info "database backed up to $bak"
  fi

  rm -rf "$PANEL_DIR/allinone.bak"
  cp -a "$PANEL_DIR/allinone" "$PANEL_DIR/allinone.bak"
  [ -f "$PANEL_DIR/VERSION" ] && cp -a "$PANEL_DIR/VERSION" "$PANEL_DIR/VERSION.bak"
  copy_panel_code
  write_panel_unit
  systemctl daemon-reload
  systemctl restart allinone
  if wait_panel; then
    rm -rf "$PANEL_DIR/allinone.bak" "$PANEL_DIR/VERSION.bak"
    UPDATE_SUMMARY="$UPDATE_SUMMARY
  面板:       ${cur:0:7} -> ${SRC_SHA:0:7}  (数据库备份: $bak)"
  else
    warn "new panel version failed to start, rolling back"
    journalctl -u allinone -n 20 --no-pager 2>/dev/null || true
    rm -rf "$PANEL_DIR/allinone"; mv "$PANEL_DIR/allinone.bak" "$PANEL_DIR/allinone"
    if [ -f "$PANEL_DIR/VERSION.bak" ]; then mv -f "$PANEL_DIR/VERSION.bak" "$PANEL_DIR/VERSION"; else rm -f "$PANEL_DIR/VERSION"; fi
    systemctl restart allinone
    if wait_panel; then
      die "update failed; rolled back to ${cur:0:7} (running). Database backup: $bak"
    fi
    die "update failed and the old version did not start either; see journalctl -u allinone. Database backup: $bak"
  fi
}

update_hysteria_node() {
  command -v iptables >/dev/null || install_pkgs iptables || warn "iptables not available: port hopping will not work"
  info "updating hysteria node sync agent"
  install_hy2_sync_agent
  write_hysteria_unit
  systemctl daemon-reload
  systemctl enable --now hy2mgr-node-sync.timer >/dev/null 2>&1
  local line="  hy2 同步:   hy2mgr-node-sync 已更新"

  if [ "$UPDATE_HY" = 1 ]; then
    local cur want
    cur="$("$HY_BIN" version 2>/dev/null | sed -n 's/^Version:[[:space:]]*//p')"
    want="$HY_VERSION"; [ "$want" = latest ] && want="$(latest_hysteria_version)"
    if [ -z "$want" ]; then
      warn "cannot determine the latest hysteria version, skipping hysteria upgrade"
    elif [ "$cur" = "$want" ]; then
      info "hysteria is up to date ($cur)"
      line="$line
  hysteria:   已是最新 $cur"
    else
      info "upgrading hysteria $cur -> $want"
      cp -a "$HY_BIN" "$HY_BIN.bak"
      HY_VERSION="$want" install_hysteria_bin
      local started; started="$(date +%s)"
      systemctl restart hysteria-server
      if wait_hysteria "$started"; then
        rm -f "$HY_BIN.bak"
        line="$line
  hysteria:   $cur -> $want"
      else
        warn "hysteria $want failed to start, rolling back to $cur"
        journalctl -u hysteria-server -n 20 --no-pager 2>/dev/null || true
        mv -f "$HY_BIN.bak" "$HY_BIN"
        systemctl restart hysteria-server
        line="$line
  hysteria:   升级到 $want 失败，已回滚到 $cur"
      fi
    fi
  fi
  systemctl start hy2mgr-node-sync >/dev/null 2>&1 || true
  UPDATE_SUMMARY="$UPDATE_SUMMARY
$line"
}

# upgrade_core NAME SERVICE VERSION_FILE WANT INSTALL_FN BIN...  (rolls back when the service won't start)
upgrade_core() {
  local name="$1" svc="$2" vfile="$3" want="$4" fn="$5"; shift 5
  local cur; cur="$(cat "$vfile" 2>/dev/null || true)"
  if [ -z "$want" ]; then warn "cannot determine the latest $name version, skipping"; return; fi
  if [ "$cur" = "$want" ]; then
    UPDATE_SUMMARY="$UPDATE_SUMMARY
  $name: 已是最新 $cur"; return
  fi
  info "upgrading $name ${cur:-?} -> $want"
  local b; for b in "$@"; do cp -a "$b" "$b.bak"; done
  "$fn" "$want"
  systemctl restart "$svc"; sleep 3
  if systemctl is-active -q "$svc"; then
    for b in "$@"; do rm -f "$b.bak"; done
    echo "$want" > "$vfile"
    UPDATE_SUMMARY="$UPDATE_SUMMARY
  $name: ${cur:-?} -> $want"
  else
    warn "$name $want failed to start, rolling back"
    for b in "$@"; do mv -f "$b.bak" "$b"; done
    systemctl restart "$svc"
    UPDATE_SUMMARY="$UPDATE_SUMMARY
  $name: 升级到 $want 失败，已回滚"
  fi
}

ss_install_tag() { install_ssrust_bin; }

update_all() {
  local panel=0 hy=0 agent=0 at=0 ss=0
  [ -f /etc/systemd/system/allinone.service ] && [ -d "$PANEL_DIR/allinone" ] && panel=1
  [ -f /etc/systemd/system/hysteria-server.service ] && [ -f "$HY_CONF_DIR/config.yaml" ] && hy=1
  [ -f /etc/systemd/system/allinone-agent.service ] && agent=1
  grep -qs allinone /etc/systemd/system/anytls-server.service && at=1
  [ -f /etc/systemd/system/ssmanager.service ] && grep -qs allinone /etc/systemd/system/ssmanager.service && ss=1
  [ $panel = 1 ] || [ $hy = 1 ] || [ $agent = 1 ] || die "nothing to update: neither the panel nor a node was installed by install.sh"
  install_pkgs curl python3 tar
  if [ $panel = 1 ] || [ $agent = 1 ]; then fetch_source; fi
  if [ $panel = 1 ]; then update_panel; fi
  if [ $hy = 1 ]; then update_hysteria_node; fi
  if [ $at = 1 ] && [ "$UPDATE_AT" = 1 ]; then
    upgrade_core anytls-server anytls-server "$AT_CONF_DIR/allinone.version" "$(latest_anytls_version)" install_anytls_bin "$AT_BIN"
  fi
  if [ $ss = 1 ] && [ "$UPDATE_SS" = 1 ]; then
    local tag; tag="$(curl -fsSLI -m 20 -o /dev/null -w '%{url_effective}' "https://github.com/$SS_REPO/releases/latest" 2>/dev/null \
                      | sed -n 's#.*/tag/\(v[0-9][0-9.]*\)$#\1#p')"
    upgrade_core shadowsocks-rust ssmanager /etc/allinone/ssrust.version "$tag" ss_install_tag "$SS_BIN_DIR/ssmanager" "$SS_BIN_DIR/ssserver"
  fi
  if [ $agent = 1 ]; then
    info "updating allinone-agent"
    install_agent_bin
    systemctl daemon-reload
    systemctl restart allinone-agent
    UPDATE_SUMMARY="$UPDATE_SUMMARY
  agent:      allinone-agent 已更新"
  fi
}

uninstall() {
  case "${1:-}" in
    panel)
      systemctl disable --now allinone 2>/dev/null || true
      rm -f /etc/systemd/system/allinone.service
      rm -rf "$PANEL_DIR/allinone" "$PANEL_DIR/.env"
      info "panel removed. Database kept at $PANEL_DIR/data, certificates in $CERT_DIR (delete them manually if not needed)";;
    node)
      systemctl disable --now allinone-agent hy2mgr-node-sync.timer hysteria-server anytls-server ssmanager 2>/dev/null || true
      for t in iptables ip6tables; do   # port hopping NAT rules
        command -v "$t" >/dev/null || continue
        "$t" -w -t nat -D PREROUTING -j HY2MGR_HOP 2>/dev/null || true
        "$t" -w -t nat -F HY2MGR_HOP 2>/dev/null || true
        "$t" -w -t nat -X HY2MGR_HOP 2>/dev/null || true
      done
      rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hy2mgr-node-sync.* \
            /usr/local/bin/hy2mgr-node-sync "$HY_BIN" /etc/sysctl.d/99-hysteria.conf \
            /etc/systemd/system/allinone-agent.service "$AGENT_BIN" "$AGENT_CONF" \
            /etc/systemd/system/anytls-server.service "$AT_BIN" \
            /etc/systemd/system/ssmanager.service "$SS_BIN_DIR/ssmanager" "$SS_BIN_DIR/ssserver"
      rm -rf "$HY_CONF_DIR" "$HY_DATA_DIR" /var/lib/allinone-agent
      info "node services removed (anytls database kept in $AT_DATA_DIR). Delete the nodes in the panel as well.";;
    *) die "usage: install.sh uninstall panel|node";;
  esac
  systemctl daemon-reload
}

# ---- main ------------------------------------------------------------------
PANEL_SUMMARY=""; NODE_SUMMARY=""; UPDATE_SUMMARY=""; FIREWALL_HINT=""; SRC_DIR=""; SRC_SHA=""; SS_TAG=""
case "$MODE" in
  panel) need_root; install_panel;;
  node)  need_root; install_node;;
  all)
    need_root
    ask DOMAIN "Panel domain (e.g. panel.example.com)"
    if [ -z "$NODE_DOMAIN" ] && [ -t 0 ]; then read -rp "Node domain (Enter = same as panel): " NODE_DOMAIN; fi
    NODE_DOMAIN="${NODE_DOMAIN:-$DOMAIN}"
    valid_domain "$NODE_DOMAIN" || die "invalid domain: $NODE_DOMAIN"
    install_panel
    PANEL_DOMAIN="$DOMAIN"; DOMAIN="$NODE_DOMAIN"
    # talk to the local panel directly, independent of DNS propagation
    PANEL_RESOLVE="$PANEL_DOMAIN:$PANEL_PORT:127.0.0.1"
    install_node;;
  update)
    need_root; update_all
    echo; info "更新完成"; echo "$UPDATE_SUMMARY"; echo; exit 0;;
  uninstall) need_root; uninstall "$UNINSTALL_WHAT"; exit 0;;
  ""|-h|--help) usage; exit 0;;
  *) usage; exit 1;;
esac

echo
info "安装完成"
[ -n "$PANEL_SUMMARY" ] && echo "$PANEL_SUMMARY"
[ -n "$NODE_SUMMARY" ] && echo "$NODE_SUMMARY"
[ -n "$FIREWALL_HINT" ] && echo "
  ${c_ylw}注意: 云服务器安全组需放行:${FIREWALL_HINT%;}${c_off}"
echo
