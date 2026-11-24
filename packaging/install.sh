#!/bin/sh
# Adds the PanelDNS package repository and installs paneldns-agent.
#
# Read this script before you run it; it does what docs/INSTALL.md lists,
# plus one check: it refuses the signing key unless its fingerprint is the
# one printed below and in the PanelDNS dashboard. Don't pipe it into a
# shell from the network: download it, read it, then run it as root.
#
#   sh install.sh                     # add the repository and install
#   sh install.sh --url URL --code - <<< 'CODE'
#                                     # ... then enrol this server, reading the
#                                     # code from standard input (a code on the
#                                     # command line is visible to every user of
#                                     # the server in the process list)
set -eu

FINGERPRINT=AAE3B3B1258CAAB0ED1AE1C3697D46A632CB9283
BASE=https://packages.paneldns.com

url="" code=""
while [ $# -gt 0 ]; do
	case "$1" in
		--url) url="$2"; shift 2 ;;
		--code) code="$2"; shift 2 ;;
		*) echo "usage: $0 [--url URL --code CODE]" >&2; exit 2 ;;
	esac
done

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
if [ "$code" = - ]; then
	IFS= read -r code || true
	[ -n "$code" ] || { echo "--code -: no code on standard input" >&2; exit 2; }
elif [ -n "$code" ]; then
	echo "warning: a code on the command line is visible to other users in the process list; use --code - <<< 'CODE'" >&2
fi
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v gpg >/dev/null || { echo "gpg is required (apt install gnupg / dnf install gnupg2)" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/gpg.key" "$BASE/gpg.key"
got="$(gpg --batch --with-colons --show-keys "$tmp/gpg.key" | awk -F: '$1 == "fpr" { print $10; exit }')"
if [ "$got" != "$FINGERPRINT" ]; then
	echo "signing key fingerprint is '$got', expected $FINGERPRINT: refusing" >&2
	exit 1
fi
echo "signing key $FINGERPRINT verified"

if command -v apt-get >/dev/null; then
	gpg --batch --yes --dearmor -o /usr/share/keyrings/paneldns.gpg "$tmp/gpg.key"
	chmod 0644 /usr/share/keyrings/paneldns.gpg
	echo "deb [signed-by=/usr/share/keyrings/paneldns.gpg] $BASE/apt stable main" > /etc/apt/sources.list.d/paneldns.list
	apt-get update
	apt-get install -y paneldns-agent
elif command -v dnf >/dev/null || command -v yum >/dev/null; then
	pm=dnf
	command -v dnf >/dev/null || pm=yum
	rpm --import "$tmp/gpg.key"
	curl -fsSL --proto '=https' --tlsv1.2 -o /etc/yum.repos.d/paneldns.repo "$BASE/rpm/paneldns.repo"
	"$pm" install -y paneldns-agent
else
	echo "neither apt-get nor dnf/yum found; use the tarball from the GitHub release" >&2
	exit 1
fi

if [ -n "$url" ] && [ -n "$code" ]; then
	PANELDNS_ENROL_CODE="$code" paneldns-agent enrol --url "$url" </dev/null
else
	echo "installed; now run: paneldns-agent enrol --url <PanelDNS URL> --code - <<< '<code>'"
fi
