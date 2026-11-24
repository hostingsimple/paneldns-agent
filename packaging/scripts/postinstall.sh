#!/bin/sh
# paneldns-agent postinstall (deb postinst, rpm %post).
# Makes sure the state directory and the config file have the modes the
# agent and --check expect, rewrites an enrolled server's unit drop-ins
# (update-units), reloads systemd, and restarts the agent and the ACL watcher
# if they are enabled (an upgrade). It never enables or starts a unit on a
# first install: `paneldns-agent enrol` does that. It downloads nothing
# (spec 7.1); update-units only resolves the PanelDNS host name.
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
	# An upgrade: rewrite this server's drop-ins before the restart, so the
	# new unit (which may deny more, such as private address ranges or
	# /home) gets the exceptions this server needs. Local files only; the
	# PanelDNS host name is looked up through the system resolver.
	if [ -f /var/lib/paneldns-agent/identity.json ]; then
		/usr/bin/paneldns-agent update-units --if-enrolled >/dev/null 2>&1 ||
			echo "paneldns-agent: update-units failed; run it by hand as root" >&2
	fi
	systemctl daemon-reload >/dev/null 2>&1 || true
	if systemctl is-enabled --quiet paneldns-agent.service 2>/dev/null; then
		systemctl try-restart paneldns-agent.service >/dev/null 2>&1 || true
	fi
	if systemctl is-enabled --quiet paneldns-agent-acl.path 2>/dev/null; then
		systemctl try-restart paneldns-agent-acl.path >/dev/null 2>&1 || true
	fi
fi
exit 0
