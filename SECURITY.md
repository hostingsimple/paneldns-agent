# Security policy

`paneldns-agent` is installed by root on hosting servers and can read every DNS zone on them, so
we treat every report seriously.

## Reporting a vulnerability

Please report privately through GitHub's **private vulnerability reporting**: open the
repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue
for a security problem.

Include the agent version (`paneldns-agent version`), the operating system, the zone source
(BIND or PowerDNS) and the steps to reproduce. We acknowledge reports within three working days.

## Supported versions

The latest release, and every release at or above the minimum version PanelDNS currently
accepts. The minimum is raised only for security fixes, with at least 14 days' notice in the
PanelDNS dashboard.

## What the agent may do

The agent's design limits are part of its security model, and a change that breaks one is a
vulnerability:

- It connects out to the configured PanelDNS URL over HTTPS only, verifying the certificate.
  There is no option to turn verification off.
- It opens no listening socket.
- It reads zone data and the panel's owner file only. It never writes zone files, named
  configuration or panel data, and never reads rndc or TSIG key files.
- It never downloads or runs code; updates come only through the OS package manager.
- Its private key is generated on the server, stored with mode 0600, and never sent anywhere.
  PanelDNS stores only the public key.

## Release signing

Release packages are built and signed on GitHub-hosted runners, in a protected environment that
needs the owner's approval. The signing key is never in this repository.
