#!/bin/sh
# paneldns-agent postremove (deb postrm, rpm %postun).
# On removal, deletes the drop-ins that enrol wrote for the agent and the ACL
# watcher (they list this server's zone directories and addresses). Reloads systemd. `dpkg --purge` also
# removes the state directory (the agent's key, so the server must be
# re-enrolled after a reinstall); the user is left in place, as Debian
# policy recommends.
set -e

# deb: remove/purge; rpm: 0 instances left. Not on upgrade.
case "${1:-}" in
	remove|purge|0)
		for d in /etc/systemd/system/paneldns-agent-acl.path.d /etc/systemd/system/paneldns-agent-acl.service.d; do
			rm -f "$d/watch.conf"
			rmdir "$d" 2>/dev/null || true
		done
		d=/etc/systemd/system/paneldns-agent.service.d
		rm -f "$d/10-paneldns-network.conf" "$d/20-paneldns-home.conf"
		rmdir "$d" 2>/dev/null || true
		;;
esac
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "${1:-}" = "purge" ]; then
	rm -rf /var/lib/paneldns-agent
fi
exit 0
