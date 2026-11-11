#!/bin/sh
# OpenIDX agent one-line installer for macOS / Linux.
#
#   curl -fsSL https://<server>/downloads/install.sh | sh -s -- \
#       --server https://<server> --code <enrollment-code>
#
# Reads the server's /downloads/agent-manifest.json, prefers the native
# package (deb on dpkg systems, rpm on rpm systems, pkg on macOS) and falls
# back to the bare binary. Every download is checked against the manifest's
# sha256 before it is installed. When --pubkey (or OPENIDX_MANIFEST_PUBKEY)
# names the release publisher's PEM public key and openssl is present, the
# manifest's X-OpenIDX-Manifest-Signature is verified first.
# POSIX sh; no bashisms.
set -eu

SERVER=""
CODE=""
DEST="${OPENIDX_DEST:-/usr/local/bin/openidx-agent}"
PUBKEY="${OPENIDX_MANIFEST_PUBKEY:-}"
FORMAT="${OPENIDX_FORMAT:-auto}"

while [ $# -gt 0 ]; do
	case "$1" in
	--server) SERVER="$2"; shift 2 ;;
	--code) CODE="$2"; shift 2 ;;
	--dest) DEST="$2"; shift 2 ;;
	--pubkey) PUBKEY="$2"; shift 2 ;;
	--format) FORMAT="$2"; shift 2 ;; # auto|deb|rpm|pkg|bin
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

[ -n "$SERVER" ] || { echo "error: --server is required" >&2; exit 2; }
[ -n "$CODE" ] || { echo "error: --code is required" >&2; exit 2; }
SERVER="${SERVER%/}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
linux | darwin) ;;
*) echo "error: unsupported OS '$os'" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "error: unsupported architecture '$arch'" >&2; exit 1 ;;
esac

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# --- manifest -------------------------------------------------------------
curl -fsSL -D "$work/headers" "$SERVER/downloads/agent-manifest.json" -o "$work/manifest.json"

# json_field KEY FIELD: the string FIELD of the manifest's top-level KEY
# object. The manifest is flat ({"k":{"url":..,"sha256":..,"filename":..}}),
# so a small awk is enough; no jq dependency.
json_field() {
	tr -d '\n' <"$work/manifest.json" | awk -v k="\"$1\"" -v f="\"$2\"" '{
		i = index($0, k ":"); if (!i) exit
		s = substr($0, i + length(k) + 1); e = index(s, "}"); s = substr(s, 1, e)
		j = index(s, f); if (!j) exit
		s = substr(s, j + length(f)); sub(/^[ \t]*:[ \t]*"/, "", s); sub(/".*/, "", s); print s
	}'
}

if [ -n "$PUBKEY" ]; then
	command -v openssl >/dev/null 2>&1 || { echo "error: --pubkey needs openssl" >&2; exit 1; }
	sig=$(awk 'tolower($1)=="x-openidx-manifest-signature:" {print $2}' "$work/headers" | tr -d '\r')
	[ -n "$sig" ] || { echo "error: the server's manifest is not signed" >&2; exit 1; }
	printf '%s' "$sig" | openssl base64 -d -A >"$work/sig"
	# Canonical input: see internal/access/downloads_sign.go.
	keys=$(tr -d '\n' <"$work/manifest.json" | grep -o '"[A-Za-z0-9_-]*":[ ]*{' | sed 's/"\([^"]*\)".*/\1/' | LC_ALL=C sort)
	{
		echo "openidx-agent-downloads-manifest/v1"
		for k in $keys; do
			for f in filename sha256 url; do echo "$k.$f=$(json_field "$k" "$f")"; done
		done
	} >"$work/signed"
	openssl dgst -sha256 -verify "$PUBKEY" -signature "$work/sig" "$work/signed" >/dev/null ||
		{ echo "error: manifest signature does not verify against $PUBKEY" >&2; exit 1; }
	echo "Manifest signature verified."
fi

# --- pick the artifact ----------------------------------------------------
if [ "$FORMAT" = auto ]; then
	if [ "$os" = darwin ]; then FORMAT=pkg
	elif command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then FORMAT=deb
	elif command -v rpm >/dev/null 2>&1 && { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v zypper >/dev/null 2>&1; }; then FORMAT=rpm
	else FORMAT=bin
	fi
fi
case "$FORMAT" in
deb | rpm) key="linux-$FORMAT-$arch" ;;
pkg) key="macos-pkg" ;;
bin) key="bin-$os-$arch" ;;
*) echo "error: unknown --format $FORMAT" >&2; exit 2 ;;
esac
url=$(json_field "$key" url)
if [ -z "$url" ] && [ "$FORMAT" != bin ]; then
	echo "No $FORMAT package for $os/$arch on this server; using the bare binary."
	FORMAT=bin key="bin-$os-$arch"
	url=$(json_field "$key" url)
fi
sha=$(json_field "$key" sha256)
name=$(json_field "$key" filename)
[ -n "$url" ] && [ -n "$sha" ] || { echo "error: the server publishes no $key artifact with a sha256" >&2; exit 1; }

echo "Downloading $SERVER$url ..."
curl -fsSL "$SERVER$url" -o "$work/$name"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$work/$name" | awk '{print $1}')
else got=$(shasum -a 256 "$work/$name" | awk '{print $1}'); fi
[ "$got" = "$sha" ] || { echo "error: sha256 mismatch for $name (got $got, manifest $sha)" >&2; exit 1; }
echo "sha256 verified."

# --- install --------------------------------------------------------------
case "$FORMAT" in
deb) $SUDO apt-get install -y "$work/$name" || $SUDO dpkg -i "$work/$name" ;;
rpm)
	if command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y "$work/$name"
	elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y "$work/$name"
	else $SUDO zypper --non-interactive install "$work/$name"; fi ;;
pkg) $SUDO installer -pkg "$work/$name" -target / ;;
bin)
	chmod +x "$work/$name"
	$SUDO install -m 0755 "$work/$name" "$DEST" ;;
esac
[ "$FORMAT" = bin ] || DEST=/usr/local/bin/openidx-agent

echo "Enrolling ..."
$SUDO "$DEST" enroll --server "$SERVER" --code "$CODE" --config-dir /var/lib/openidx-agent
if [ "$os" = linux ] && [ -d /run/systemd/system ]; then
	$SUDO chown -R openidx-agent:openidx-agent /var/lib/openidx-agent 2>/dev/null || true
	$SUDO systemctl restart openidx-agent.service 2>/dev/null || true
fi
echo "Done. The OpenIDX agent is installed and enrolled."
