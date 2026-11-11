package snapshot

import "strings"

// scriptText runs the same commands as the collector table in collect.go. Keep the two in step.
const scriptText = `#!/bin/sh
# Seaward snapshot: prints the output of read-only listing commands as one text file.
# It changes nothing on this machine and sends nothing anywhere. Read it, then run:
#   sudo sh seaward-snapshot.sh > snapshot.txt
# Without root it still runs, but the firewall rules and process names are left out.
LC_ALL=C; export LC_ALL
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG # describe this machine, never a remote one
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
set -f # no file name expansion of command output
errors=""
o=""

has() { command -v "$1" >/dev/null 2>&1; }
tmo=""; has timeout && tmo="timeout 5" # one hung tool must not stall the snapshot

# out NAME BODY: print one section. A body line that could pass for a header gets one more space.
out() {
	printf '### %s\n' "$1"
	if [ -n "$2" ]; then printf '%s\n' "$2" | sed 's/^ *### / &/'; fi
}

# get NAME COMMAND...: if the command exists, run it and keep its output in $o; a failure is noted.
get() {
	o=""
	name=$1; shift
	has "$1" || return 1
	o=$($tmo "$@" </dev/null 2>/dev/null); rc=$?
	# docker inspect fails when one container stopped meanwhile; the other lines still count.
	if [ $rc -ne 0 ] && { [ "$name" != docker-net ] || [ -z "$o" ]; }; then
		errors="$errors$name: exit status $rc
"
		o=""
		return 1
	fi
}

# run NAME COMMAND...: the same, and print the output as a section.
run() { get "$@" && out "$name" "$o"; }

# mask: takes the hardware (MAC) addresses out of the interface list; nothing is read from
# them. In turn: six or seven pairs of hex digits, nine or more (eight could be an IPv6
# address), the tail of a bridge id, an alternative name made from the address (enx...), and a
# device id in the shape of a UUID.
mask() {
	sed @MASKS@
}

root=no; [ "$(id -u 2>/dev/null)" = 0 ] && root=yes
echo '# seaward snapshot 1'
out meta "host $(hostname 2>/dev/null || uname -n)
seaward @VERSION@
collector script
root $root"

# Packet rules.
run iptables-version iptables -V
legacy=no; case $o in *"(legacy)"*) legacy=yes ;; esac
run iptables-save iptables-save
run ip6tables-save ip6tables-save
if [ $legacy = no ]; then
	# The legacy tables are separate kernel tables; include them only when they hold something.
	# A listing that fails is noted like any other: rules may sit where nobody could look.
	for t in iptables-legacy-save ip6tables-legacy-save; do
		if get $t $t && printf '%s\n' "$o" | grep -q '^\*'; then out $t "$o"; fi
	done
fi
run nft-json nft -j list ruleset
run ipset-save ipset save

# The machine.
run ss ss -Htulpn
if get ip-addr ip -j -d addr show; then out ip-addr "$(printf '%s\n' "$o" | mask)"; fi
run ip-route-4 ip -j -4 route show table main
run ip-route-6 ip -j -6 route show table main
if has sysctl; then
	s1=$(sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding 2>/dev/null)
	# busybox sysctl has no -r; then the full list is filtered instead.
	s2=$(sysctl -a -r 'net\.ipv4\.conf\..*\.route_localnet' 2>/dev/null ||
		sysctl -a 2>/dev/null | grep '^net\.ipv4\.conf\..*\.route_localnet')
	s3=$(printf '%s\n%s\n' "$s1" "$s2" | grep .)
	if [ -n "$s3" ]; then out sysctl "$s3"; fi
fi

# Docker. The inspect template names its fields one by one: container settings hold
# environment variables, which often hold passwords, and they must never be printed.
if has docker; then
	run docker-version docker version --format '{{.Server.Version}}'
	if run docker-ps docker ps --no-trunc --format '@PS@'; then
		ids=$(printf '%s\n' "$o" | sed -n 's/.*"ID":"\([0-9a-f]*\)".*/\1/p')
		if [ -n "$ids" ] && run docker-net docker inspect --format '@TEMPLATE@' $ids; then
			net=$o
			if [ $root = yes ] && has nsenter; then
				while read -r id pid mode rest; do
					# A host-network container's listeners are already in the host's ss.
					case $id:$mode:$pid in *[!0-9a-f]*:*:* | *:host:* | *:*:0 | *:*:*[!0-9]* | *:*:) ;;
					*) run "docker-ss $id" nsenter -t "$pid" -n ss -Htulpn ;; esac
				done <<EOF
$net
EOF
			fi
		fi
	fi
fi

# Firewall managers.
run ufw-status ufw status verbose
if has firewall-cmd; then
	# It exits non-zero and prints "not running" when firewalld is stopped: an answer, not a failure.
	st=$($tmo firewall-cmd --state </dev/null 2>&1)
	case $st in running | "not running") out firewalld-state "$st" ;; *) errors="${errors}firewalld-state: failed
" ;; esac
	if [ "$st" = running ]; then
		run firewalld-active firewall-cmd --get-active-zones
		if run firewalld-zones firewall-cmd --list-all-zones; then
			# Services of the active zones and the default zone; of every zone if none is marked.
			todo=$(printf '%s\n' "$o" | awk '/^[^ \t]/ { act = /[(,] *(active|default)/; any = any || act }
				/^  services:/ { for (i = 2; i <= NF; i++) { all = all " " $i; if (act) mine = mine " " $i } }
				END { print (any ? mine : all) }')
			seen=" "
			while [ -n "$todo" ]; do
				set -- $todo; [ $# -gt 0 ] || break
				s=$1; shift; todo=$*
				case $seen in *" $s "*) continue ;; esac
				seen="$seen$s "
				if run "firewalld-service $s" firewall-cmd --info-service="$s"; then
					todo="$todo $(printf '%s\n' "$o" | sed -n 's/^ *includes://p')"
				fi
			done
		fi
	fi
fi

if [ -n "$errors" ]; then out errors "${errors%?}"; fi
`

func script() string {
	return strings.NewReplacer("@VERSION@", Version, "@TEMPLATE@", dockerInspectTemplate, "@PS@", dockerPSTemplate,
		"@MASKS@", maskSed()).Replace(scriptText)
}
