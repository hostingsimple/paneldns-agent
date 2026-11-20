#!/bin/sh
# paneldns-agent preremove (deb prerm, rpm %preun).
# Stops and disables the unit when the package is removed, not when it is
# upgraded. No network access: PanelDNS is not told; decommission the
# server in the dashboard (spec 10.12).
set -e

case "${1:-}" in
	remove|purge|0)
		if [ -d /run/systemd/system ]; then
			systemctl disable --now paneldns-agent.service >/dev/null 2>&1 || true
		fi
		;;
esac
exit 0
