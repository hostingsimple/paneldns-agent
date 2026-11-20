#!/bin/sh
# paneldns-agent preinstall (deb preinst, rpm %pre).
# Creates the paneldns-agent system user and group before the files are
# unpacked, so /etc/paneldns-agent.conf and /var/lib/paneldns-agent get
# their group and owner. No network access, no downloads (spec 7.1).
set -e

if ! getent group paneldns-agent >/dev/null 2>&1; then
	groupadd --system paneldns-agent
fi
if ! getent passwd paneldns-agent >/dev/null 2>&1; then
	nologin=/usr/sbin/nologin
	[ -x "$nologin" ] || nologin=/sbin/nologin
	useradd --system --gid paneldns-agent --no-create-home \
		--home-dir /var/lib/paneldns-agent --shell "$nologin" \
		--comment "PanelDNS agent" paneldns-agent
fi
exit 0
