# Changelog

## 0.1.1

An independent review of 0.1.0 found ten defects. All ten are fixed here. A second review, of
the fixes, found one more of the same kind (a rewrite behind a jump), a long range whose ports
did not all fare alike, and a report that claimed too much when a scan stopped at a ceiling;
those are fixed here too. Several of these could make a reachable port look closed, so a server
scanned with 0.1.0 is worth scanning again.

What a scan gets right now:

- **Chains on the ingress hook are followed.** nftables can drop a packet as it arrives on an
  interface, before every other chain (`hook ingress`, in a netdev or an inet table). 0.1.0 left
  those chains out, so a port they drop was reported as reachable.
- **A chain Seaward does not follow is named, and decides nothing.** An egress chain, a chain of a
  bridge table, an ingress chain underneath a bridge, a bond or a VLAN: a port whose packets pass
  one is undecided and the report lists the chain under "not followed". When all such a chain can
  do is drop packets, the report still says how the packet ends in the rules that were followed.
- **DNAT and REDIRECT to a range of ports** work as in the kernel: a packet keeps the port it came
  for when that lies in the range, and gets the first port of the range when it does not. 0.1.0
  always took the first port. A port picked at random, or a range of addresses, makes the port
  undecided and says why.
- **Addresses the machine holds on other interfaces are asked about**: a spare address on the
  loopback or on a dummy interface, a bridge's address. Linux answers for every address it holds,
  whichever interface the packet arrives on. 0.1.0 asked only about the addresses of the interface
  itself, so a service bound to a floating address looked closed.
- **Every port a rule sends somewhere else is asked about.** 0.1.0 looked at the first four ports
  of such a rule and at 48 of them in all, at the two ends of a range only, never into a named
  set, and only at the rule that does the rewriting. Now every port counts, in the rule or in a
  set it looks up, and the scan goes the way a packet goes before routing: from the rule that
  names the port through every jump, goto and verdict map to the chain that rewrites, which is
  how Kubernetes, firewalld and many hand-written rulesets are laid out. A port named again in
  the chain jumped to has to pass both rules. A statement Seaward cannot follow in that place
  (TPROXY) is asked about as well, and is undecided. What remains: a scan has rows for TCP and
  UDP ports only, and the ceiling is 4,096 ports.
- **A long range of ports is asked where something changes.** A range of more than 16 ports is
  asked at its two ends and at every port inside it that a rule, a listener or the target range
  of a rewrite sets apart, and the report names the range. A port asked there stands for the
  ports up to the next one asked, so a count that includes one reads "at least 3 ports".
  `seaward why PORT` answers for any port of such a range, not only for the ones in the report,
  and for a port the scan did not come to before its ceiling of ports.
- **Every sender the rules single out is asked about.** 0.1.0 told at most twelve groups of
  senders apart, looked at the first six ranges of a set and at the first sixteen entries of a
  verdict map, all without a word: of sixteen addresses let in by sixteen rules it found eleven.
  Now every stretch of addresses the rules tell apart is covered, a set of thousands of addresses
  is searched as fast as a small one, and the ceiling is 1,024 groups of senders from one place.
- **A scan that stopped at a ceiling says so first and claims nothing beyond it.** The report
  lists what was not asked at its top ("not asked"; `partial` in `--json`; a box of its own in
  the demo). The headline reads "Nothing was found reachable from outside, but not every sender
  was asked." or "At least 3 ports can be reached from outside." A port that no sender that was
  asked reaches is undecided and reached by "nobody that was asked"; a port some senders reach
  is reached by "at least" those. `seaward scan --check` exits with status 4, never 0.
- **A long list of senders stays readable.** More than four are written as the first three and how
  many others: "198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only". `--json` still has
  a packet for every one. In a narrow terminal, who reaches a port goes on to a second line; it is
  no longer cut off.
- **An undecided packet lists the ways it can end only when all of them are known.** One that
  stopped at a rule Seaward cannot follow no longer reads as "can only be dropped", and when a
  packet may leave by one of two interfaces, a chain that was not followed on either is named.

Snapshots and the command line:

- **Snapshots mask hardware (MAC) addresses** in the interface list: addresses, bridge ids,
  alternative names made from an address, UUID device ids. A snapshot taken by 0.1.0 holds them as
  printed.
- **A failing `iptables-legacy-save` is written down**, and that family of rules counts as unread.
- **`seaward why` refuses a malformed port.** `22/tcp/udp` used to be read as udp; `tcp/5432` and
  `udp 53` are no longer accepted and get a message with the right spelling.
- **`seaward why PORT --json`** prints that port's packets as JSON, with `--from` as well. An
  option given to a command that has no use for it (`--check` with `why`) is an error and no
  longer passed over in silence.
- **The terminal report** uses the full width, breaks a long rule before an option, lists what the
  firewall manager was told under its own name ("ufw's list"), and quotes a file name that needs
  it in the command it suggests. That command keeps the protocol that was asked for.

The demo, the proof and the build:

- **The demo** shows the chains that were not followed and how a packet ends otherwise. A long
  rule wraps inside its box, and the boxes are measured again when the window changes size. A
  lane that many named senders reach says how many they are; their names stand in its row.
- **Checked against the real kernel**: 80 scenarios (67 before) and 40 random rulesets, 2,105 real
  packets, 0 disagreements. The thirteen new scenarios cover ingress chains, rewrites to a range
  of ports, a rewrite behind a jump, a goto and a verdict map, a target range inside a long range
  of ports, addresses on the loopback and on a bridge, many senders let in one by one, and
  senders told apart by a set. The lab now holds the scan to the kernel as well as the engine:
  a port the kernel answers on has to be a port the scan asks about and calls reachable.
  1,194 automated tests (964 before).
- **CI** runs every step with `pipefail`.

## 0.1.0

The first release.

- **`seaward scan`**: every port on the machine, who can reach it (the internet, the local network,
  VPN peers, one address range, nobody) and the rule or policy that decides it. Ports that are
  reachable although the firewall manager does not allow them come first.
- **`seaward why PORT`**: one packet followed through the kernel's path rule by rule, from the
  interface it arrives on to the program or container that answers. `--from ADDR` follows a packet
  from one sender.
- **Reads what is really loaded**: iptables rules (nf_tables and legacy), native nftables with
  sets, maps and verdict maps, ipsets, Docker's chains and published ports, ufw and firewalld.
- **Snapshots**: `seaward snapshot` saves what a scan reads as one text file, and
  `seaward snapshot --script` prints the collector as a shell script, so a server can be read
  without installing anything on it. A snapshot reads on Linux and macOS. One taken with sudo is
  written as whoever ran sudo, after root has been given up, and holds no container command lines,
  environments or labels.
- **Says when it does not know**: a rule beyond the model makes the port undecided, with the reason.
  Rules that could not be read (no root) decide nothing.
- **`--check`** for CI and cron: exit status 3 when a port is exposed, 4 when something is undecided.
- **`--json`**: the full report, with every step of every packet.
- **Checked against the real kernel**: 67 scenarios and 40 random rulesets are built in private
  network namespaces, real packets are sent through them, and the result is compared with the
  engine's answer on every change.
- **Checked on whole machines**: on every change a CI machine turns ufw on, and another firewalld,
  lets Docker publish a port neither allows, and compares what Seaward says with what real
  connections from outside do.
- **A live demo** that runs the engine in the browser on sample machines or a snapshot of your own.
