#!/bin/sh
# paneldns-agent postinstall (deb postinst, rpm %post).
# Makes sure the state directory and the config file have the modes the
# agent and --check expect, reloads systemd, and restarts the unit if it is
# enabled (an upgrade). It never enables or starts the unit on a first
# install: `paneldns-agent enrol` does that. No network access (spec 7.1).
set -e

# deb calls this with "configure" (and others such as "abort-upgrade");
# rpm with the number of installed instances.
case "${1:-}" in
	configure|abort-upgrade|abort-remove|abort-deconfigure|[0-9]*) ;;
	*) exit 0 ;;
esac

install -d -m 0700 -o paneldns-agent -g paneldns-agent /var/lib/paneldns-agent
if [ -f /etc/paneldns-agent.conf ]; then
	chown root:paneldns-agent /etc/paneldns-agent.conf
	chmod 0640 /etc/paneldns-agent.conf
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if systemctl is-enabled --quiet paneldns-agent.service 2>/dev/null; then
		systemctl try-restart paneldns-agent.service >/dev/null 2>&1 || true
	fi
fi
exit 0
