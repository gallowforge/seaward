# Seaward: design notes

Seaward answers one question about a Linux server: **which ports can really be reached from outside,
and which rule decides it.** It reads what the machine already knows (the kernel's packet rules, the
listening sockets, Docker's published ports, what ufw or firewalld say they allow), walks a packet
through the rules the way the kernel does, and reports every port with the rule that let it in or
stopped it. It never changes anything and never sends a packet.

This file is the contract between the packages. Keep it true.

## Ground rules

- **Read-only.** The collector runs listing commands only. No command that changes state, ever.
- **Zero dependencies** outside the Go standard library. `go 1.24`.
- **Nothing private in the repository.** Every sample and fixture uses documentation addresses
  (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`, `2001:db8::/32`) for public addresses and
  invented names (`web-1`, `eth0`, `postgres`). Private ranges (`10/8`, `172.16/12`, `192.168/16`)
  are fine where a real set-up would have them (Docker's `172.17.0.0/16`). Never copy output from
  the machine you are developing on into a file.
- **Never collect secrets.** No `docker inspect` without a `--format` template that names the exact
  fields; container environment variables must never enter a snapshot.
- **Honest unknowns.** Anything the model cannot decide becomes `rules.Unknown` or
  `rules.UnknownStmt` with one plain sentence. The engine follows both outcomes; the report says
  "depends on" instead of guessing. A parser must never drop a condition silently.
- **Plain words** in everything a user reads. Short sentences. No jargon without the plain meaning
  beside it.

## Packages

| Package | Job |
| --- | --- |
| `internal/rules` | The firewall model (tables, chains, rules as expression lists). Written; do not change without updating this file. |
| `internal/host` | The machine model (interfaces, routes, listeners, Docker, the firewall manager). Written. |
| `internal/ipt` | `iptables-save`, `ip6tables-save` and `ipset save` text into `rules`. |
| `internal/nft` | `nft -j list ruleset` JSON into `rules`. |
| `internal/snapshot` | The snapshot bundle (read, write), the collector that produces it, and the parsers for everything that is not a firewall rule (`ss`, `ip`, `sysctl`, Docker, ufw, firewalld). `Build` turns a bundle into a `rules.Ruleset` and a `host.Host`. |
| `internal/engine` | Walks one packet through the model (`Run`), and the analysis that decides which packets to try and what the result means (`Analyze`). |
| `internal/lab` | Proof. Loads rulesets into the real kernel inside throwaway network namespaces, sends real packets, and compares what happened with what the engine said. |
| `cmd/seaward` | The command line. |
| `cmd/seaward-wasm`, `web/` | The same engine in the browser, for the demo page. |

## The snapshot bundle

A snapshot is one plain text file: the output of well-known read-only commands, each under a header
line. Anyone can read it before sharing it, and a shell script can produce it without installing
anything.

```
# seaward snapshot 1
### meta
host web-1
### iptables-version
iptables v1.8.10 (nf_tables)
### iptables-save
*filter
...
### ss
tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))
```

A section starts at a line `### <name>` or `### <name> <argument>` and runs to the next such line.
The first line of the file is `# seaward snapshot 1`. Lines before the first section that start with
`#` are comments. A body line that would start with `### ` is written with one leading space.

| Section | Command | Notes |
| --- | --- | --- |
| `meta` | (written by the collector) | `key value` lines: `host`, `seaward` (version), `collector` (`cli` or `script`), `root` (`yes`/`no`) |
| `iptables-version` | `iptables -V` | says `(nf_tables)` or `(legacy)` |
| `iptables-save` | `iptables-save` | |
| `ip6tables-save` | `ip6tables-save` | |
| `iptables-legacy-save` | `iptables-legacy-save` | only when the default is nf_tables and the legacy tool exists and prints rules |
| `ip6tables-legacy-save` | `ip6tables-legacy-save` | same |
| `nft-json` | `nft -j list ruleset` | one JSON document |
| `ipset-save` | `ipset save` | |
| `ss` | `ss -Htulpn` | host listeners |
| `ip-addr` | `ip -j -d addr show` | JSON; `-d` gives `linkinfo.info_kind` |
| `ip-route-4` | `ip -j -4 route show table main` | JSON |
| `ip-route-6` | `ip -j -6 route show table main` | JSON |
| `sysctl` | `sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` then `sysctl -a -r 'net\.ipv4\.conf\..*\.route_localnet'` | `key = value` lines |
| `docker-version` | `docker version --format '{{.Server.Version}}'` | |
| `docker-ps` | `docker ps --no-trunc --format '{{json .}}'` | one JSON object per line |
| `docker-net` | `docker inspect --format '<template>' <ids>` | one line per container: `<id> <pid> <network mode> <network>=<ipv4>\|<ipv6> ...` The template names these fields only. |
| `docker-ss <container id>` | `nsenter -t <pid> -n ss -Htulpn` | listeners inside one container; needs root |
| `ufw-status` | `ufw status verbose` | |
| `firewalld-state` | `firewall-cmd --state` | |
| `firewalld-zones` | `firewall-cmd --list-all-zones` | |
| `firewalld-active` | `firewall-cmd --get-active-zones` | |
| `errors` | (written by the collector) | `section: message` for each command that was missing, failed or timed out |

A command that does not exist on the machine produces no section and no error (no Docker is not an
error). A command that exists and fails (not root) produces an `errors` line; the report then says
what it could not see.

## The firewall model

See `internal/rules/rules.go`; the comments there are the specification. The points parsers must agree on:

- **Base chains of iptables tables** (both the nf_tables and the legacy backend):

  | Table | Chains | Type | Priority |
  | --- | --- | --- | --- |
  | `raw` | PREROUTING, OUTPUT | filter | -300 |
  | `mangle` | PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING | filter (OUTPUT: route) | -150 |
  | `nat` | PREROUTING, OUTPUT | nat | -100 |
  | `nat` | INPUT, POSTROUTING | nat | 100 |
  | `filter` | INPUT, FORWARD, OUTPUT | filter | 0 |
  | `security` | INPUT, FORWARD, OUTPUT | filter | 50 |

  `Chain.Hook` is the lower-case hook name. The policy comes from the `:CHAIN POLICY [n:n]` line.
  `Table.Family` is `ip` for iptables, `ip6` for ip6tables. `Table.Origin` is `iptables` or
  `iptables-legacy`.

- **One expression per condition, in the order written.** `Rule.Text` is the original line
  (`-A CHAIN ...` for iptables; nft syntax for nft, rebuilt if need be).
- **Protocol** is `FL4Proto` with the protocol number. **Ports** are `FSport` / `FDport`; a port
  match on its own does not imply a protocol, so the parser emits the protocol match too when the
  source implies one (`-p tcp -m tcp --dport 80` is two matches: protocol 6, dport 80).
- **Addresses** are `AtomPrefix` (a single address is a /32 or /128) or `AtomRange`.
- **Interfaces**: `eth+` (iptables) and `eth*` (nft) are `AtomStrPfx("eth")`.
- **Connection state** (`-m conntrack --ctstate NEW,RELATED`, `-m state`, `ct state`) is
  `Eq(FCtState, Num(CtNew), Num(CtRelated))`. A probe is `CtNew`.
- **Marks**: `--mark 0x1/0xff` is `Match{Key: [{FMark, Mask 0xff, HasMask true}], Values: One(Num(1))}`.
- **Things that are true for a first packet** are `Always`: `-m limit`, `-m hashlimit` (the burst
  lets the first packet through), `-m comment`, `-m recent --set`, `connlimit --connlimit-upto`.
- **Things that are false for a first packet** are `Never`: `-m recent --rcheck/--update` (the
  sender has never been seen), `--connlimit-above`, `-f` (fragments). With `!` in front they
  become `Always`.
- **Statements that do not decide anything** are `Noop`: LOG, NFLOG, counters, MASQUERADE, SNAT,
  TCPMSS, CLASSIFY, TRACE, SET (adding to a set), and so on. A rule with no target is just its matches.
- **NOTRACK / `CT --notrack` / `notrack`** is `Notrack`.
- **Anything else** (an extension or target not listed in the parser's table) is `Unknown` (a
  match) or `UnknownStmt` (a target), with a sentence such as
  `"the string match (-m string) looks inside the packet"`.
- **ipsets**: `-m set --match-set NAME src,dst` becomes a `Match` with `SetRef: SetKey("", "", NAME)`
  and a key built from the set's type: an `ip`/`net` dimension is `FSaddr` or `FDaddr`, a `port`
  dimension is two fields (`FL4Proto`, then `FSport` or `FDport`), an `iface` dimension is
  `FIifName` or `FOifName`. A set that was not captured is `Unknown`.

## The walk (`engine.Run`)

One packet: the first packet of a new connection (TCP SYN or one UDP datagram), arriving on a named
interface, from one source address to one destination address and port.

1. **Prerouting.** Every base chain on the prerouting hook whose table sees this packet's family
   (`ip` sees IPv4, `ip6` sees IPv6, `inet` sees both), lowest priority first. In a filter chain,
   drop ends everything and accept moves to the next base chain. In a nat chain the first DNAT or
   REDIRECT that runs rewrites the destination and no later nat chain on this hook is consulted.
2. **Routing.** If the destination is now one of this machine's addresses, the packet goes to
   input. A destination in `127.0.0.0/8` arriving from outside is dropped unless `route_localnet`
   is set for the arriving interface. Otherwise it is forwarded: that needs forwarding switched on
   and a route; the route gives the output interface.
3. **Input** base chains, then the listening sockets: a socket takes the packet if protocol and port
   match and it is bound to that address, to every address of that family, or to `::` with
   dual-stack for IPv4, and, when it is bound to one interface, the packet arrived there.
   **Or forward** base chains, then postrouting filter chains, then delivery: to a container when
   the destination is a container's address, else onward to another machine.
4. **Unknowns.** When a condition is `Unknown` the walk follows both answers (up to a cap). If every
   branch ends the same way the result stands; otherwise the result is `Undecided` and names what it
   hangs on.

Results: `Open` (a program received it), `Closed` (it got through and nothing was listening),
`Rejected` (a rule refused it out loud), `Filtered` (dropped without a word), `Forwarded` (let
through to another machine), `Undecided`.

What the walk does not model, and says so: replies (it assumes the answer can leave), rate limits
beyond the first packet, bridge filtering (`br_netfilter`), eBPF programs (XDP, tc, cgroup), IPVS,
policy routing (only the main table is read), IPsec, and anything in front of the machine (a cloud
firewall, a router).

## The proof (`internal/lab`)

A scenario is a ruleset, a set of listeners and a list of probes. The lab builds it for real inside
network namespaces that vanish when the test ends: a `host` namespace with the rules and listeners,
a `peer` namespace on the other end of a virtual cable playing the internet, and where needed a
`ctr` namespace behind a bridge playing a container. It takes a snapshot there with the real
collector, sends every probe as a real packet, and records what happened: connected, refused, or
silence. Then the engine reads the snapshot and predicts each probe. Any difference fails the test.

Safety rule, enforced in code: the lab refuses to run a single command unless it is inside a fresh
network namespace (a marker in the environment and no interface other than `lo` at the start).
It must be impossible for it to touch the rules of the machine it runs on.
