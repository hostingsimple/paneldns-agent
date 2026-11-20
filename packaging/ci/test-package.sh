#!/bin/sh
# Runs inside a clean distribution container (CI packages job): installs the
# snapshot package with the native tool, checks what it put on disk, checks
# that a reinstall keeps an edited config, and removes it.
#
#   test-package.sh deb|rpm /dist
set -eu

kind="$1"
dist="$2"
arch="$(uname -m)"
fail() { echo "FAIL: $*" >&2; exit 1; }

case "$kind" in
	deb)
		pkg="$(ls "$dist"/paneldns-agent_*_amd64.deb | head -n 1)"
		install() { dpkg -i "$pkg"; }
		reinstall() { dpkg -i "$pkg"; }
		remove() { dpkg -r paneldns-agent; }
		;;
	rpm)
		pkg="$(ls "$dist"/paneldns-agent-*."$arch".rpm | head -n 1)"
		install() { rpm -i "$pkg"; }
		reinstall() { rpm -U --replacepkgs "$pkg"; }
		remove() { rpm -e paneldns-agent; }
		;;
	*) fail "kind must be deb or rpm" ;;
esac
echo "== installing $pkg"
install

getent passwd paneldns-agent >/dev/null || fail "user paneldns-agent missing"
getent group paneldns-agent >/dev/null || fail "group paneldns-agent missing"
[ -x /usr/bin/paneldns-agent ] || fail "binary missing"
/usr/bin/paneldns-agent version
[ -f /usr/lib/systemd/system/paneldns-agent.service ] || fail "unit missing"
[ "$(stat -c '%a %U %G' /etc/paneldns-agent.conf)" = "640 root paneldns-agent" ] \
	|| fail "config mode/owner: $(stat -c '%a %U %G' /etc/paneldns-agent.conf)"
[ "$(stat -c '%a %U %G' /var/lib/paneldns-agent)" = "700 paneldns-agent paneldns-agent" ] \
	|| fail "state dir mode/owner: $(stat -c '%a %U %G' /var/lib/paneldns-agent)"
[ -f /usr/share/doc/paneldns-agent/LICENSE ] || fail "LICENSE missing"

# --check runs (and fails: nothing is enrolled here).
if /usr/bin/paneldns-agent --check > /tmp/check.txt 2>&1; then
	fail "--check passed on a server that is not enrolled"
fi
grep -q "not enrolled" /tmp/check.txt || { cat /tmp/check.txt; fail "--check output"; }

echo "== reinstall keeps an edited config"
sed -i 's/^INTERVAL=60 /INTERVAL=120 /' /etc/paneldns-agent.conf
grep -q '^INTERVAL=120 ' /etc/paneldns-agent.conf || fail "test edit not applied"
reinstall
grep -q '^INTERVAL=120 ' /etc/paneldns-agent.conf || fail "upgrade replaced the edited config"

echo "== remove"
remove
[ ! -e /usr/bin/paneldns-agent ] || fail "binary left after removal"
echo "OK: $pkg"
