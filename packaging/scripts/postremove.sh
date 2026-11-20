#!/bin/sh
# paneldns-agent postremove (deb postrm, rpm %postun).
# Reloads systemd. `dpkg --purge` also removes the state directory (the
# agent's key, so the server must be re-enrolled after a reinstall); the
# user is left in place, as Debian policy recommends.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "${1:-}" = "purge" ]; then
	rm -rf /var/lib/paneldns-agent
fi
exit 0
