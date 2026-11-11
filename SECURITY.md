# Security

Seaward is run as root on servers, so what it does there is kept small enough to read in one sitting.

## The model

Seaward reads. It never adds, changes or removes a firewall rule, never opens a port and never sends
a packet. It answers from what the machine already says about itself.

A scan runs a fixed list of listing commands, each with a five second limit, and nothing else:

| Command | What it is read for |
| --- | --- |
| `iptables-save`, `ip6tables-save`, the `-legacy` pair, `iptables -V` | the packet rules |
| `nft -j list ruleset` | the nftables rules |
| `ipset save` | the sets those rules refer to |
| `ss -Htulpn` | what is listening, and which program |
| `ip -j -d addr show`, `ip -j route show table main` | interfaces, addresses, routes |
| `sysctl` for `ip_forward`, `forwarding`, `route_localnet` | whether packets are passed on |
| `docker version`, `docker ps`, `docker inspect` with a fixed template | containers, their networks and published ports |
| `nsenter -t PID -n ss -Htulpn` | what listens inside each container |
| `ufw status verbose`, `firewall-cmd` listings | what the firewall manager believes |

No command line is built from anything the machine prints, apart from container ids, a container's
process id and firewalld service names, and each of those is checked against a strict pattern first. `DOCKER_HOST`, `DOCKER_CONTEXT`
and `DOCKER_CONFIG` are dropped, so a scan describes this machine and never a remote one.

`seaward snapshot --script` prints the same list as a plain shell script of about 120 lines, for a
machine you would rather not put a binary on. Read it before you run it.

## What a snapshot holds

A snapshot is one text file with the output of those commands. It holds firewall rules, interface
addresses, routes, listening ports with program names, container names, images and published ports.

It does not hold container environment variables, command lines, file contents, keys or passwords.
`docker inspect` is called with a template that names its fields one by one for exactly that reason:
container settings are where passwords live.

Addresses and host names are in it. Treat a snapshot like a network diagram: fine to hand to a
colleague, not something to paste in public.

## What could go wrong

| What could go wrong | What prevents it |
| --- | --- |
| A scan changes the firewall | There is no code path that writes. The command list is fixed and every command in it is a listing. |
| A hung tool stalls a server login | Every command has a five second limit; a failure is written down in the snapshot and the scan carries on. |
| A hostile snapshot file attacks the reader | The readers are plain parsers with no shell, no network and no file access beyond the one file. They are fuzzed; a rule they cannot follow is reported as undecided, never guessed. |
| The live demo leaks a snapshot you paste | The page is static and the engine runs in your tab as WebAssembly. Its Content-Security-Policy allows connections to its own origin only. |
| A wrong answer is trusted | See below. |

## What this does not protect

Seaward is a model of the kernel's packet path, checked against the real kernel in CI, and it says
"undecided" when a rule is beyond it. It is still a model. It does not see a cloud security group, a
router or anything else in front of the machine, and it does not model eBPF programs, IPVS, policy
routing or IPsec. The README lists the limits in full. A port it calls closed is closed as far as
the rules it read can tell; confirm anything that matters with a real connection from outside.

## Reporting a problem

Please report a vulnerability privately to ali@gallowforge.dev rather than in a public issue.
Expect a reply within a week.
