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
		contents() { dpkg-deb -c "$pkg"; }
		;;
	rpm)
		pkg="$(ls "$dist"/paneldns-agent-*."$arch".rpm | head -n 1)"
		install() { rpm -i "$pkg"; }
		reinstall() { rpm -U --replacepkgs "$pkg"; }
		remove() { rpm -e paneldns-agent; }
		contents() { rpm -qlp "$pkg"; }
		;;
	*) fail "kind must be deb or rpm" ;;
esac

# D-32: acl is a dependency. The native tool refuses the package without it, which is the
# point; first prove that, then install acl from the distribution as apt/dnf would.
echo "== refused without acl"
if ! command -v setfacl >/dev/null 2>&1; then
	if install >/dev/null 2>&1; then fail "installed without its acl dependency"; fi
	[ "$kind" = deb ] && dpkg -r paneldns-agent >/dev/null 2>&1 || true
fi
case "$kind" in
	deb) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends acl >/dev/null ;;
	rpm) command -v setfacl >/dev/null 2>&1 || dnf install -y -q acl >/dev/null ;;
esac
echo "== installing $pkg"
install

getent passwd paneldns-agent >/dev/null || fail "user paneldns-agent missing"
getent group paneldns-agent >/dev/null || fail "group paneldns-agent missing"
[ -x /usr/bin/paneldns-agent ] || fail "binary missing"
/usr/bin/paneldns-agent version
[ -f /usr/lib/systemd/system/paneldns-agent.service ] || fail "unit missing"
for u in paneldns-agent-acl.path paneldns-agent-acl.service; do
	[ -f "/usr/lib/systemd/system/$u" ] || fail "$u missing"
done
[ "$(stat -c '%a %U %G' /etc/paneldns-agent.conf)" = "640 root paneldns-agent" ] \
	|| fail "config mode/owner: $(stat -c '%a %U %G' /etc/paneldns-agent.conf)"
[ "$(stat -c '%a %U %G' /var/lib/paneldns-agent)" = "700 paneldns-agent paneldns-agent" ] \
	|| fail "state dir mode/owner: $(stat -c '%a %U %G' /var/lib/paneldns-agent)"
# The licence ships in the package. Checked in the package's file list, not on
# disk: Ubuntu's minimal images exclude /usr/share/doc/* via dpkg path-exclude.
contents | grep -q '/usr/share/doc/paneldns-agent/LICENSE$' || fail "LICENSE not in package"
contents | grep -q '/usr/share/doc/paneldns-agent/NOTICE$' || fail "NOTICE not in package"

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

echo "== remove deletes the drop-ins enrol wrote (ACL watcher and agent)"
mkdir -p /etc/systemd/system/paneldns-agent-acl.path.d /etc/systemd/system/paneldns-agent-acl.service.d /etc/systemd/system/paneldns-agent.service.d
echo "[Path]" > /etc/systemd/system/paneldns-agent-acl.path.d/watch.conf
echo "[Service]" > /etc/systemd/system/paneldns-agent-acl.service.d/watch.conf
echo "[Service]" > /etc/systemd/system/paneldns-agent.service.d/10-paneldns-network.conf
echo "[Service]" > /etc/systemd/system/paneldns-agent.service.d/20-paneldns-home.conf
remove
[ ! -e /usr/bin/paneldns-agent ] || fail "binary left after removal"
[ ! -e /etc/systemd/system/paneldns-agent-acl.path.d ] || fail "path drop-in left after removal"
[ ! -e /etc/systemd/system/paneldns-agent-acl.service.d ] || fail "service drop-in left after removal"
[ ! -e /etc/systemd/system/paneldns-agent.service.d ] || fail "agent drop-ins left after removal"
echo "OK: $pkg"
