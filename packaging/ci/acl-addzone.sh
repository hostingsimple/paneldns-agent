# Sourced by the integration workflow's ACL steps (not run on its own).
#
# addzone NAME adds a zone to /srv/acl/named.conf and writes its zone file
# the way cPanel does: mode 0600 and owned by another user (nobody here,
# named on cPanel). The directory's default ACL still gives the file a
# user:paneldns-agent:r entry, but the 0600 mode sets its mask to ---.

addzone() {
	printf 'zone "%s" { type primary; file "%s.db"; };\n' "$1" "$1" | sudo tee -a /srv/acl/named.conf >/dev/null
	printf '$TTL 300\n@ IN SOA ns1.example.net. hostmaster.example.net. 1 3600 600 86400 300\n@ IN NS ns1.example.net.\n@ IN A 192.0.2.10\n' |
		sudo tee "/srv/acl/$1.db" >/dev/null
	sudo chmod 0600 "/srv/acl/$1.db"
	sudo chown nobody:"$(id -gn nobody)" "/srv/acl/$1.db"
}

# hasacl FILE LINE fails unless `getfacl -c FILE` has exactly that line.
hasacl() {
	acl="$(sudo getfacl -c "$1")"
	printf '%s\n' "$acl" | grep -qx -- "$2" || { printf '%s\n' "$acl"; echo "$1: no ACL line $2" >&2; return 1; }
}
