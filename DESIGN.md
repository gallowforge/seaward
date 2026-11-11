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
| `internal/engine` | Walks one packet through the model (`Run`) and says how it ended, step by step. |
| `internal/scan` | Decides which packets to try (which ports, from where, from whom), runs them and turns the results into the report: one finding per port, in plain words. Also the terminal rendering. |
| `internal/lab` | Proof. Loads rulesets into the real kernel inside throwaway network namespaces, sends real packets, and compares what happened with what the engine said. |
| `cmd/seaward` | The command line. |
| `cmd/seaward-wasm`, `web/` | The same engine in the browser, for the demo page. |
| `samples/` | Invented machines as snapshots: the demo's examples, the README's pictures and test fixtures in one. |

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
`#` are comments. A body line that starts with any number of spaces and then `### ` is written with
one more leading space, so no command output can pass for a header; the reader takes that space off
again. A file that went through a Windows editor (CRLF line ends, a byte order mark) still reads.
`Parse` answers `ErrNotSnapshot` for anything else, and names the format number when it is one this
version does not read.

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
| `firewalld-service <name>` | `firewall-cmd --info-service=<name>` | one per service of the active and default zones, and of the services those include |
| `errors` | (written by the collector) | `section: message` for each command that was missing, failed or timed out |

A command that does not exist on the machine produces no section and no error (no Docker is not an
error). A command that exists and fails (not root) produces an `errors` line; the report then says
what it could not see.

The collector exists twice and the two must stay in step: `Collect` in Go, and `Script`, the same
list as a POSIX shell script for a machine nobody wants to put a binary on. Both set `LC_ALL=C`,
give each command five seconds, and drop `DOCKER_HOST`, `DOCKER_CONTEXT` and `DOCKER_CONFIG` so the
snapshot describes this machine and never a remote one. The only values that travel from command
output into a command line are container ids (hex only), a container's process id (digits only) and
firewalld service names (checked by `safeName`). `argvFor` is the only place a command line is built.

### What `Build` adds

- A host socket with no program name, in a snapshot taken as root, belongs to **the kernel**
  (WireGuard, NFS): `Listener.Process` is `"the kernel"`. Without root the name is simply unknown.
- `Host.NoListenerData` is set when the snapshot has no socket list at all; `Container.ListenersKnown`
  when a container's own sockets were read. Without them the report cannot say "nothing is listening".
- **Rule sources nobody could read** go to `Ruleset.Unread`, each with one sentence
  (`"The IPv4 packet rules (iptables) could not be read: iptables-save needs root."`). Five cases:
  a listing that will not parse; an nft document that will not parse (both families); an `errors`
  line for a rule section; an iptables listing that says a table is "incompatible" while the nft
  listing is missing; no rule section at all in a snapshot taken without root. Rules nobody read may
  stop or redirect anything, so **the engine decides nothing for a family while one of its sources
  is unread**.

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
- **IPv6 extension headers** (`-m rt`, `frag`, `hbh`, `dst`, `ah`) are `Never`: a probe carries
  none. `-m ipv6header` and `-m hl` stay `Unknown`.
- **Address types seen from one interface** (`addrtype --limit-iface-in`, `fib daddr . iif type`)
  are `FFibDaddrTypeIif` / `FFibSaddrTypeIif`: an address of another interface of this machine is
  not local there. The lab found this one.
- **ipsets**: `-m set --match-set NAME src,dst` becomes a `Match` with `SetRef: SetKey("", "", NAME)`
  and a key built from the set's type: an `ip`/`net` dimension is `FSaddr` or `FDaddr`, a `port`
  dimension is two fields (`FL4Proto`, then `FSport` or `FDport`), an `iface` dimension is
  `FIifName` or `FOifName`. A set that was not captured is `Unknown`.

### Reading nftables (`internal/nft`)

`nft.ParseJSON(data, shared)` reads `nft -j list ruleset`. `shared` is what `iptables-save` gave for
the tables iptables itself made on the nf_tables backend, because neither listing is complete on its
own:

- The nft listing shows most of what iptables wrote as `xt` expressions that carry a name and
  nothing else. For those rules iptables-save is the only reading.
- The `nft` tool can add rules to the same tables, and **iptables-save 1.8.13 misprints what it has
  no words for without any warning**: `tcp dport { 25, 587 } accept` comes out as
  `-A INPUT -p tcp -j ACCEPT`, a lookup in a named set as an unconditional `-A INPUT -j ACCEPT`, a
  verdict map as a rule with no target. A reader that trusts iptables-save alone reports those
  ports wrongly.

So the two are **settled rule by rule** (`settle.go`): chains, order, hooks, priorities and policies
come from the nft listing; each rule comes from iptables-save when it holds an `xt` expression or is
written entirely the way iptables-nft writes rules, and from the nft listing otherwise. The listings
are matched by position, which holds only while they agree on a chain's length; where they do not,
the chain is read from the nft listing alone, its `xt` parts become `Unknown`, and a note says so.

It reads `ip`, `ip6` and `inet` tables; named, anonymous, interval and concatenated sets; verdict
maps; reject, dnat, redirect, mark set and copy, limits, notrack. Other families (`bridge`, `arp`,
`netdev`) are noted and skipped. What the model is too thin for, each reported and never guessed:
data-map values (a `dnat to ... map`), masks with gaps, the mark in `fib saddr . mark . iif`; dnat
to a range uses the first address.

**Verdict maps and `continue`, as the kernel does it:** a verdict map with no entry for the packet
ends the rule, like a failed match. An entry that says `continue` goes on to the next expression of
the same rule, and so does a plain `continue` verdict. `Set.Verdicts` holds a named map's verdicts,
one per element.

## The walk (`engine.Run`)

One packet: the first packet of a new connection (TCP SYN or one UDP datagram), arriving on a named
interface, from one source address to one destination address and port.

1. **Prerouting.** Every base chain on the prerouting hook whose table sees this packet's family
   (`ip` sees IPv4, `ip6` sees IPv6, `inet` sees both), lowest priority first. In a filter chain,
   drop ends everything and accept moves to the next base chain. In a nat chain the first DNAT or
   REDIRECT that runs rewrites the destination and no later nat chain on this hook is consulted.
   All nat chains of a hook really run at one fixed place (-100 on prerouting and output, 100 on
   input and postrouting); a nat chain's declared priority only orders it among the other nat
   chains. Connection tracking starts at -200: a chain before it sees a packet with no connection
   yet, and a packet marked `notrack` there is never rewritten.
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
through to another machine), `Undecided` (with `Result.Possible`: the ways it can end).

Every result carries its `Steps`: each rule that matched, each jump into another chain, each policy,
the routing decision and the delivery, with the rule's own text and what it did in plain words
(`"destination becomes 172.18.0.2:5432"`, `"policy drop: no rule let it through"`).
`Result.Deciding()` picks the one step that settled the packet and `Result.Rewrite()` the rule that
sent it somewhere else. Those two are what the report shows.

What the walk does not model, and says so: replies (it assumes the answer can leave), the
`rp_filter` sysctl and martian sources, rate limits beyond the first packet, bridge filtering
(`br_netfilter`), eBPF programs (XDP, tc, cgroup), IPVS, policy routing (only the main table is
read), IPsec, DHCP broadcast, and anything in front of the machine (a cloud firewall, a router).
A probe leaves from an ordinary high port, so a rule that accepts by source port is not flagged.

## The report (`internal/scan`)

`scan.Run(rs, h)` returns a `Report`; `Report.Text` renders it for a terminal and `--json` prints
it as it is.

1. **Where packets can come from.** One vantage per outside interface and kind: `world` (the
   internet behind a default route), `lan` (the network the interface is plugged into), `vpn`
   (WireGuard, tun and the like). Interfaces that lead to the machine's own containers (veth,
   bridges, `docker0`) are inside, not a vantage.
2. **Who is sending.** The rules tell senders apart by address (a prefix, a set, the firewall
   manager's own list). Every such condition is collected; one address stands for "everyone else"
   and one more for each group some rule singles out. Two senders no rule tells apart get the same
   treatment everywhere, so this is exhaustive for source addresses, not a sample.
3. **Which ports.** Everything that listens on the machine, every port Docker publishes, every port
   a DNAT or redirect rule names, and every port the firewall manager mentions.
4. **One finding per port**, from all its packets together:

   | Finding | Meaning |
   | --- | --- |
   | `exposed` | reachable from outside although the firewall manager does not allow it |
   | `open` | reachable from outside, and allowed |
   | `limited` | reachable for some senders only (a network, a set, VPN peers) |
   | `undecided` | hangs on something the model cannot see; the reason is given |
   | `local` | reachable from this machine only |
   | `blocked` | something listens and the rules stop every packet |
   | `shadowed` | the firewall manager allows it, yet an earlier rule stops it |
   | `dead` | allowed or published, and nothing answers |
   | `closed` | nothing listens and nothing is let through |

   `Port.Reach` says who gets through in a few words (`"the internet"`, `"the local network on lan0
   only"`, `"VPN peers only"`, `"the set admins only"`), `Port.Stated` what the firewall manager
   says, `Port.Why` the reason in a sentence, and `Port.Cells` every packet tried with all its steps.

Three things about the firewall manager's side of it:

- **A zone is said once.** firewalld's default zone covers every interface no other zone names, so
  one opening arrives as one rule per interface. When those add up to every outside interface the
  port is `allowed`, not "allowed only on eth0, on eth1 ...". An interface the owner wrote into a
  ufw rule stays as written.
- **Link-local and multicast openings are listed, not asked about.** firewalld's stock
  `dhcpv6-client` service allows udp 546 to `fe80::/64`. The scan sends nothing to link-local or
  multicast addresses, so that opening shows in the manager's list (`546/udp to fe80::/64`) and is
  no reason to add a port to the report.
- **A named sender arrives where the routes say.** `scan.Trace` (`seaward why PORT --from ADDR`)
  follows one packet from one address, on whichever interface the routes give for it, including an
  interface the scan leaves out as inside.

## The command line (`cmd/seaward`)

`scan`, `why PORT[/PROTO]`, `snapshot -o FILE`, `snapshot --script`, `version`; `-f FILE` reads a
snapshot (`-` is standard input), so `ssh server sudo seaward snapshot | seaward scan -f -` reads a
server from a laptop. Reading a snapshot works on any system; taking one needs Linux.

Exit status: 0 fine, 1 an error, 2 wrong usage. With `--check`: 3 when a port is exposed, 4 when
nothing is exposed but something is undecided or unread. Colour only on a terminal; `NO_COLOR` and
`--no-color` are honoured.

## The browser build (`cmd/seaward-wasm`)

One global function, `seawardScan(snapshotText)`, returns one JSON string:
`{"ok": true, "version": "...", "report": {...}}` or `{"ok": false, "error": "..."}`. A panic becomes
an error. `seawardReady()` is called once when the engine is loaded, if the page defines it. The
page is static, has no server and its Content-Security-Policy allows connections to its own origin
only: a snapshot pasted into it stays in the tab.

## The proof (`internal/lab`)

A scenario is a ruleset, a set of listeners and a list of probes. The lab builds it for real inside
network namespaces that vanish when the test ends: a `host` namespace with the rules and listeners,
a `peer` namespace on the other end of a virtual cable playing the internet, and where needed a
`ctr` namespace behind a bridge playing a container. It takes a snapshot there with the real
collector, sends every probe as a real packet, and records what happened: connected, refused, or
silence. Then the engine reads the snapshot and predicts each probe. Any difference fails the test.

Safety rule, enforced in code twice: the launcher refuses any command line that does not start the
shell through `unshare` with a new network and mount namespace (`checkArgv`), and the first lines of
every scenario script refuse to go on without the launcher's marker or when anything but `lo` exists
(the guard). It must be impossible for the lab to touch the rules of the machine it runs on.

Run it with `make lab`. It needs no root: `unshare -Urnm` gives each scenario its own user, network
and mount namespace. On a CI runner, where unprivileged user namespaces may be switched off,
`SEAWARD_LAB_SUDO=1` uses `sudo unshare -n -m`, still never outside a fresh namespace.

A scenario is a text file in `internal/lab/scenarios/`: `name:`, `about:`, the rules as
`--- iptables`, `--- ip6tables` or `--- nft`, the listeners, and the probes, each with the outcome a
person expects (`want:open`, `want:refused`, `want:silent`). A want that the kernel contradicts fails
the test too: that is how a wrong belief about the kernel gets caught, not only a wrong engine.
After the written scenarios, `gen.go` writes random rulesets from the same vocabulary and compares
those as well.

| Setting | |
| --- | --- |
| `SEAWARD_LAB_RANDOM=N` | how many random rulesets (default 40) |
| `SEAWARD_LAB_SEED=S` | the seed for them; a failure prints the seed that reproduces it |
| `SEAWARD_LAB_ONLY=regexp` | run only the scenarios whose name matches |
| `SEAWARD_LAB_WORKERS=N` | scenarios at once (default: the CPUs, at most 12) |
| `SEAWARD_LAB_KEEP=dir` | keep each scenario's script, snapshot and results |
| `SEAWARD_LAB_SUMMARY=path` | write the totals as JSON |
| `SEAWARD_LAB_TIMEOUT_MS` | how long a probe waits before it counts as silent (default 900) |

### Whole machines

The lab proves the engine on rulesets written for it. Two CI jobs prove the whole tool on a machine
nobody wrote for it: a GitHub runner with ufw, then one with firewalld, each allowing ssh and port
9001, with Docker publishing nginx on 8080 and plain listeners on 9000 and 9001. Seaward has to
say `exposed`, `blocked` and `open` for the three, `--check` has to exit 3, `why --from` has to
agree for the one outside sender, and then real connections from a namespace on the other end of a
cable have to do the same. `internal/scan/testdata/firewalld-docker.snapshot` is the firewalld
runner as the collector saw it, kept as a test.

### What the kernel taught

Each of these was a disagreement the lab found; each is now a scenario.

1. A rule that drops a published port in `DOCKER-USER` by its outside number (`--dport 8080`)
   matches nothing: by then the packet carries the container's port (80). `--ctorigdstport 8080`
   is the one that works.
2. A packet already rewritten to a container is dropped without a word when `ip_forward` is 0.
3. DNAT to `127.0.0.1` is dropped unless `route_localnet` is set for the arriving interface.
4. REDIRECT rewrites to the address of the interface the packet arrived on, not to the address it
   was sent to.
5. An address of `eth1` reached through `eth0` is not local as `eth0` sees it
   (`--limit-iface-in`, `fib daddr . iif type local`).
6. A rule that rejects established packets lets the first packet through; the connection then dies
   on the client's next packet. The port is reachable for a scanner and useless for a client.
7. A verdict map with no matching entry ends the rule; `continue` goes on within the rule.
8. For the lab itself: a new namespace inherits IPv4 sysctls from the one that made it; TCP over
   IPv6 treats an ICMPv6 "unreachable" as a soft error while connecting; the kernel limits ICMP
   errors per namespace, so one refusal in a burst goes missing unless `icmp_ratemask` is cleared;
   and a "silent" probe must never be retried, because a rate limit lets only the first packet pass.

## Docker's rules, by version

The samples and the wording about Docker follow the Engine's source, not folklore:

- A port published without an address binds every address and gets a DNAT rule in chain `DOCKER` of
  table `nat`; the packet is then forwarded, so `INPUT`, where ufw keeps its list, never sees it.
- A port published on `127.0.0.1` gets, from Engine 28.0.0, a rule in table `raw` that drops it
  unless it arrived on `lo` (`-d 127.0.0.1/32 ! -i lo -p tcp --dport N -j DROP`). Before 28 a
  machine on the same network could reach such a port by routing to it.
- `DOCKER-FORWARD`, `DOCKER-BRIDGE` and `DOCKER-CT` appear in 28.0.1. `DOCKER-INTERNAL` exists from
  29.0.0, which also removes `DOCKER-ISOLATION-STAGE-1` and `-2`. `samples/shop-1.snapshot` shows a
  29 layout and says so.
- Docker's nftables backend is experimental in 29; Seaward reads its tables like any other nft
  table and has not been checked against it on a real daemon.
