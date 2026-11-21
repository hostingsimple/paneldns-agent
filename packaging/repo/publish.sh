#!/bin/sh
# Builds the signed APT and YUM repository tree of hostingsimple/paneldns-packages
# (spec 7.12) in a checkout of that repository. Run only by the release
# workflow's sign-and-publish job, after the signing key is imported.
#
# Environment:
#   MODE        release (add the packages in $DIST) or resign (metadata only)
#   DIST        directory with the signed .deb and .rpm files (release mode)
#   REPO        checkout of paneldns-packages to update
#   AGENT       checkout of paneldns-agent (for gpg.key and paneldns.repo)
#   SIGN_FPR    fingerprint of the signing key's primary (gpg picks the subkey)
#   PASSFILE    file holding the subkey passphrase
#   GNUPGHOME   the throw-away keyring
#   KEEP        versions kept per architecture and format (default 5)
#   VALID_DAYS  APT Valid-Until, in days (default 30; spec 7.10, owner decision 2026-11-21)
set -eu

: "${MODE:?}" "${REPO:?}" "${AGENT:?}" "${SIGN_FPR:?}" "${PASSFILE:?}" "${GNUPGHOME:?}"
KEEP="${KEEP:-5}"
VALID_DAYS="${VALID_DAYS:-30}"

gpgsign() {
	gpg --batch --yes --pinentry-mode loopback --passphrase-file "$PASSFILE" \
		--local-user "$SIGN_FPR" --digest-algo SHA512 "$@"
}

cd "$REPO"
pool=apt/pool/main/p/paneldns-agent
mkdir -p "$pool" apt/dists/stable/main/binary-amd64 apt/dists/stable/main/binary-arm64 \
	rpm/x86_64 rpm/aarch64

if [ "$MODE" = release ]; then
	: "${DIST:?}"
	found=0
	for f in "$DIST"/*.deb; do [ -e "$f" ] && cp "$f" "$pool/" && found=1; done
	for f in "$DIST"/*.x86_64.rpm; do [ -e "$f" ] && cp "$f" rpm/x86_64/ && found=1; done
	for f in "$DIST"/*.aarch64.rpm; do [ -e "$f" ] && cp "$f" rpm/aarch64/ && found=1; done
	[ "$found" = 1 ] || { echo "no packages in $DIST" >&2; exit 1; }
elif [ "$MODE" != resign ]; then
	echo "MODE must be release or resign" >&2
	exit 1
fi

# Pruning (spec 7.12): keep the newest $KEEP versions per architecture and
# format. Git history keeps the removed files.
prune() {
	# shellcheck disable=SC2086
	ls -1 $1 2>/dev/null | sort -V | head -n "-$KEEP" | while read -r old; do
		echo "pruning $old"
		rm -f -- "$old"
	done
}
prune "$pool/*_amd64.deb"
prune "$pool/*_arm64.deb"
prune "rpm/x86_64/*.rpm"
prune "rpm/aarch64/*.rpm"

# ---- APT ---------------------------------------------------------------
(
	cd apt
	for arch in amd64 arm64; do
		out="dists/stable/main/binary-$arch"
		apt-ftparchive --arch "$arch" packages pool > "$out/Packages"
		gzip -9 -n -c "$out/Packages" > "$out/Packages.gz"
	done
	rm -f dists/stable/Release dists/stable/Release.gpg dists/stable/InRelease
	apt-ftparchive \
		-o APT::FTPArchive::Release::Origin=PanelDNS \
		-o APT::FTPArchive::Release::Label=PanelDNS \
		-o APT::FTPArchive::Release::Suite=stable \
		-o APT::FTPArchive::Release::Codename=stable \
		-o APT::FTPArchive::Release::Architectures="amd64 arm64" \
		-o APT::FTPArchive::Release::Components=main \
		-o "APT::FTPArchive::Release::Description=PanelDNS agent packages" \
		release dists/stable > Release.tmp
	until="$(LC_ALL=C date -u -d "+${VALID_DAYS} days" '+%a, %d %b %Y %H:%M:%S UTC')"
	# Valid-Until goes right after Date; apt refuses the metadata after it.
	awk -v u="Valid-Until: $until" '{ print } /^Date:/ { print u }' Release.tmp > dists/stable/Release
	rm -f Release.tmp
	grep -q '^Valid-Until:' dists/stable/Release
	gpgsign --clearsign --output dists/stable/InRelease dists/stable/Release
	gpgsign --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
)

# ---- YUM ---------------------------------------------------------------
# Clients expire the metadata after a day (metadata_expire=1d in
# paneldns.repo) and check repomd.xml.asc (repo_gpgcheck=1).
for d in rpm/x86_64 rpm/aarch64; do
	rm -rf "$d/repodata"
	createrepo_c --quiet --general-compress-type=gz "$d"
	gpgsign --armor --detach-sign --output "$d/repodata/repomd.xml.asc" "$d/repodata/repomd.xml"
done

# ---- Static files --------------------------------------------------------
cp "$AGENT/packaging/gpg.key" gpg.key
cp "$AGENT/packaging/repo/paneldns.repo" rpm/paneldns.repo
printf 'packages.paneldns.com\n' > CNAME
cat > README.md <<'EOF'
# PanelDNS agent packages

Signed APT and YUM repository for `paneldns-agent`, served at
https://packages.paneldns.com. This repository is written only by the
release workflow of https://github.com/hostingsimple/paneldns-agent;
do not edit it by hand. Install instructions:
https://github.com/hostingsimple/paneldns-agent/blob/main/docs/INSTALL.md
EOF

# Self-check: the metadata verifies against the published public key.
check="$(mktemp -d)"
gpg --homedir "$check" --batch --quiet --import gpg.key
gpg --homedir "$check" --batch --verify apt/dists/stable/InRelease
gpg --homedir "$check" --batch --verify apt/dists/stable/Release.gpg apt/dists/stable/Release
for d in rpm/x86_64 rpm/aarch64; do
	gpg --homedir "$check" --batch --verify "$d/repodata/repomd.xml.asc" "$d/repodata/repomd.xml"
done
rm -rf "$check"
echo "repository tree updated (mode $MODE, Valid-Until in $VALID_DAYS days)"
