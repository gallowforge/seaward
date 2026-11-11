# Changelog

## Unreleased

Nothing yet.

## 0.1.0

The first release.

- **`seaward scan`**: every port on the machine, who can reach it (the internet, the local network,
  VPN peers, one address range, nobody) and the rule or policy that decides it. Ports that are
  reachable although the firewall manager does not allow them come first.
- **`seaward why PORT`**: one packet followed through the kernel's path rule by rule, from the
  interface it arrives on to the program or container that answers.
- **Reads what is really loaded**: iptables rules (nf_tables and legacy), native nftables with
  sets, maps and verdict maps, ipsets, Docker's chains and published ports, ufw and firewalld.
- **Snapshots**: `seaward snapshot` saves what a scan reads as one text file, and
  `seaward snapshot --script` prints the collector as a shell script, so a server can be read
  without installing anything on it. A snapshot reads on Linux and macOS.
- **Says when it does not know**: a rule beyond the model makes the port undecided, with the reason.
  Rules that could not be read (no root) decide nothing.
- **`--check`** for CI and cron: exit status 3 when a port is exposed, 4 when something is undecided.
- **`--json`**: the full report, with every step of every packet.
- **Checked against the real kernel**: 67 scenarios and 40 random rulesets are built in private
  network namespaces, real packets are sent through them, and the result is compared with the
  engine's answer on every change.
- **A live demo** that runs the engine in the browser on sample machines or a snapshot of your own.
