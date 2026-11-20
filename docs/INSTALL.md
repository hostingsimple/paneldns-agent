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
sudo paneldns-agent enrol --url https://app.paneldns.example --code <code from the dashboard>
```

[`packaging/install.sh`](../packaging/install.sh) runs the same commands, refuses a key with a
different fingerprint, and can enrol in one go. Download it, read it, then run it as root; never
pipe it into a shell.

## Other systems

Each GitHub release carries `paneldns-agent_<version>_linux_<arch>.tar.gz` (binary, unit file,
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

`apt remove paneldns-agent` / `dnf remove paneldns-agent` stops the service; the package tells
PanelDNS nothing, so decommission the server in the dashboard as well.
