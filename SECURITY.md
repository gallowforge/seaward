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
| `docker version`, and `docker ps` and `docker inspect` each with a fixed template | containers, their networks and published ports |
| `nsenter -t PID -n ss -Htulpn` | what listens inside each container |
| `ufw status verbose`, `firewall-cmd` listings | what the firewall manager believes |

No command line is built from anything the machine prints, apart from container ids, a container's
process id and firewalld service names, and each of those is checked against a strict pattern first. `DOCKER_HOST`, `DOCKER_CONTEXT`
and `DOCKER_CONFIG` are dropped, so a scan describes this machine and never a remote one.

`seaward snapshot --script` prints the same list as a plain shell script of about 135 lines, for a
machine you would rather not put a binary on. Read it before you run it.

## What a snapshot holds

A snapshot is one text file with the output of those commands. It holds the machine's host name,
its firewall rules, its interfaces with their IP addresses, its routes, its listening ports with
program names, and the name, image and published ports of each container.

It does not hold container environment variables, command lines, labels, mounts, file contents,
keys or passwords. `docker ps` and `docker inspect` are each called with a template that names its
fields one by one for exactly that reason: container settings are where passwords live. From
`docker ps` that is six fields: id, name, image, published ports, networks and state.

Hardware (MAC) addresses are masked. `ip` prints them in several places and Seaward reads none of
them, so the binary and the script both put x's in their place before anything is kept:

- the address of each interface, the one a card was made with, and any other address printed the
  same way (a bond's, a virtual function's): `xx:xx:xx:xx:xx:xx`
- the address inside a bridge id: `8000.xx:xx:xx:xx:xx:xx`
- an alternative name the system made from the address, which recent versions of systemd give a
  card: `enxxxxxxxxxxxxx`
- a device id in the shape of a UUID, which on an Azure virtual machine is made from the address
  of its network card: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

The rest of what `ip` prints is kept as printed. Some of it still points at one machine, and some
of it still gives a hardware address away:

- **Interface names**, and their alternative names other than the one above. An interface whose
  own name the system made from its hardware address (`enx` and twelve hex digits, as some USB
  adapters are named) keeps that name, because the rules and the routes are written in terms of it.
- **Where each card is plugged in**: the bus and the place on it, such as PCI slot `0000:01:00.0`.
- **Every IP address.** An IPv6 address that the kernel built from the hardware address still
  shows it. Unless the machine is set up otherwise, that is the link-local address of each
  interface (`fe80::` with `ff:fe` in the middle of what follows), and a global address formed
  the same way.
- **A hardware address eight bytes long.** The mask knows an address by its shape, six bytes or
  more written as pairs of hex digits, and an IPv6 address can be written as eight such pairs.
  Only a few low-power radios have an address like that.

The mask is for the interface list alone. Firewall rules, sets and firewalld zones are kept word
for word, since they are what Seaward reads: a rule or a set that names a MAC address still names
it.

Version 0.1.0 masked nothing: a snapshot it took holds every hardware address as `ip` printed it.

So treat a snapshot like a network diagram: fine to hand to a colleague, not something to paste in
public. `seaward snapshot -o` writes the file readable by its owner alone, whatever was under that
name before.

Root is for reading the rules, not for writing the file. Under sudo, once the listing commands have
run, Seaward gives up root for good and writes the file as the person who ran sudo. The scan that
follows needs no root, and `-o` can write nothing that person could not have written themselves.
The file is written beside its name and moved into place, so a link planted under that name is
never followed, and a name that is a link, a device or a directory is refused.

## What could go wrong

| What could go wrong | What prevents it |
| --- | --- |
| A scan changes the firewall | There is no code path that writes. The command list is fixed and every command in it is a listing. |
| `-o` under sudo overwrites a file that belongs to root | The file is written after root has been given up, as the person who ran sudo. If root cannot be given up, nothing is written. |
| A hung tool stalls a server login | Every command has a five second limit; a failure is written down in the snapshot and the scan carries on. |
| A hostile snapshot file attacks the reader | The readers are plain parsers with no shell, no network and no file access beyond the one file. They are fuzzed; a rule they cannot follow is reported as undecided, never guessed. |
| The live demo leaks a snapshot you paste | The page is static and the engine runs in your tab as WebAssembly. Its Content-Security-Policy allows connections to its own origin only. |
| A wrong answer is trusted | See below. |

## What this does not protect

Seaward is a model of the kernel's packet path, checked against the real kernel in CI, and it says
"undecided" when a rule is beyond it. It is still a model. It does not see a cloud security group, a
router or anything else in front of the machine, and it does not model eBPF programs, IPVS, policy
routing or IPsec. The README lists the limits in full. A scan that reaches one of its two ceilings
(1,024 groups of senders from one place, 4,096 ports) lists at the top what it did not ask, calls
nothing closed that it did not ask about, and exits with status 4 under `--check`. A port it calls
closed is closed as far as the rules it read can tell; confirm anything that matters with a real
connection from outside.

## Reporting a problem

Please report a vulnerability privately to ali@gallowforge.dev rather than in a public issue.
Expect a reply within a week.
