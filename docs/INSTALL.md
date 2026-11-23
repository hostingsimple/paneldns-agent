# Installing paneldns-agent

The agent is published as signed `.deb` and `.rpm` packages at `https://packages.paneldns.com`
(spec 7.1, 7.12). `apt` and `dnf` check every package and the repository metadata against the
signing key, and refuse anything unsigned, tampered with or stale.

**Signing key fingerprint:** `AAE3 B3B1 258C AAB0 ED1A  E1C3 697D 46A6 32CB 9283`

Check it before trusting the key:

```sh
curl -fsSL https://packages.paneldns.com/gpg.key | gpg --show-keys
```

## Debian, Ubuntu

```sh
curl -fsSL https://packages.paneldns.com/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/paneldns.gpg
echo "deb [signed-by=/usr/share/keyrings/paneldns.gpg] https://packages.paneldns.com/apt stable main" | sudo tee /etc/apt/sources.list.d/paneldns.list
sudo apt update && sudo apt install -y paneldns-agent
```

`unattended-upgrades` installs only from the distribution's own origins by default. To update the
agent automatically, add to `/etc/apt/apt.conf.d/51paneldns`:

```
Unattended-Upgrade::Origins-Pattern { "origin=PanelDNS,label=PanelDNS"; };
```

## RHEL, Rocky, Alma (dnf)

```sh
sudo rpm --import https://packages.paneldns.com/gpg.key
sudo curl -fsSLo /etc/yum.repos.d/paneldns.repo https://packages.paneldns.com/rpm/paneldns.repo
sudo dnf install -y paneldns-agent
```

The `.repo` file sets `gpgcheck=1`, `repo_gpgcheck=1` and `metadata_expire=1d`. With
`dnf-automatic` (`upgrade_type = default`) updates arrive automatically.

## Enrol

```sh
sudo paneldns-agent enrol --url https://app.paneldns.example --code - <<< '<code from the dashboard>'
```

`--code -` reads the code from standard input. A code written as `--code <code>` also works, but
while enrol runs every user of the server can read it in the process list (`ps`), and someone
who sends it to PanelDNS first enrols a key of their own; enrol warns when it gets the code that
way. `PANELDNS_ENROL_CODE` works too, but not through `sudo VAR=value`, which puts it back on a
command line.

[`packaging/install.sh`](../packaging/install.sh) runs the same commands, refuses a key with a
different fingerprint, and can enrol in one go. Download it, read it, then run it as root; never
pipe it into a shell.

## The ACL watcher

The agent runs as the unprivileged `paneldns-agent` user and reads zone files through the POSIX
ACLs enrol grants. Panels don't always keep them: cPanel creates every new zone file with mode
0600, which sets the file's ACL mask to `---` and so cancels the read entry the file inherits
from its directory (`getfacl` shows `user:paneldns-agent:r--  #effective:---`), and a file the
panel replaces with a new one loses its ACL altogether.

Enrol therefore also enables `paneldns-agent-acl.path`. It watches the zone directories and the
directories of named.conf, its includes and the owner file, and on any change starts
`paneldns-agent-acl.service`, which runs `paneldns-agent fix-acls` as root. That re-grants only
the agent's read access where it is missing (the agent's entry plus the read bit of the mask)
on the files and directories enrol planned; it never touches key files and never lowers a mask,
so a group's write access stays. Its log is one line per run.

Check it:

```sh
systemctl status paneldns-agent-acl.path
journalctl -u paneldns-agent-acl.service -n 20
paneldns-agent --check     # reports the watcher, and zone files the agent can't read
```

The watched directories differ per server. Enrol writes them to
`/etc/systemd/system/paneldns-agent-acl.path.d/watch.conf`, and the paths the service may change
to `/etc/systemd/system/paneldns-agent-acl.service.d/watch.conf`. When the panel adds a zone in a
new directory (HestiaCP, for a new hosting user), `--check` and the service's log say the watch
list is out of date; run `sudo paneldns-agent fix-acls` once by hand to fix the ACLs, rewrite
both drop-ins and restart the watcher. `sudo paneldns-agent fix-acls` is also the manual fix
whenever `--check` reports unreadable zone files.

With `--no-acl` or `--no-start`, enrol writes the drop-ins but doesn't enable the watcher; enable
it with `systemctl enable --now paneldns-agent-acl.path`. If a burst of changes ever trips its
trigger limit, `systemctl status` shows it failed; `systemctl restart paneldns-agent-acl.path`
starts it again.

## Other systems

Each GitHub release carries `paneldns-agent_<version>_linux_<arch>.tar.gz` (binary, unit files,
sample config), `SHA256SUMS` and `SHA256SUMS.asc`:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify paneldns-agent_<version>_linux_amd64.tar.gz --repo hostingsimple/paneldns-agent
```

## Verify a build yourself

Check out the release tag and build with the release flags; the binary inside the package must
match byte for byte:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -buildid= -X github.com/hostingsimple/paneldns-agent/internal/version.Version=<version>" \
  -o paneldns-agent ./cmd/paneldns-agent
```

## Downgrade in an emergency

`apt install paneldns-agent=<version>` or `dnf downgrade paneldns-agent`. Normally a bad release
is fixed by a newer version (spec 7.12).

## Remove

`apt remove paneldns-agent` / `dnf remove paneldns-agent` stops the service and the ACL watcher
and removes the watcher's drop-ins; the ACLs already granted stay. The package tells PanelDNS
nothing, so decommission the server in the dashboard as well.
