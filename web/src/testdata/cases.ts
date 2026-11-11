// Small reports for the states the samples do not reach. Every address is a documentation address.
import type { Cell, Port, Report } from '../types'

const CAVEAT = "Read from this machine's own rules. Anything in front of it (a cloud firewall, a router) is not seen."
const internet = { id: 'internet', label: 'the internet', short: 'internet', iface: '', scope: 'world' } as const
const none = { reachable: 0, exposed: 0, stopped: 0, quiet: 0, undecided: 0 }

/** A machine on which nothing listens. */
export const nothingListens: Report = {
  host: 'bare-1',
  headline: 'Nothing listens on this machine.',
  vantages: [internet],
  ports: [],
  counts: none,
  caveat: CAVEAT,
}

/** What the engine answers for a snapshot with no network interfaces in it: nowhere to ask from. */
export const noInterface: Report = {
  host: 'bare-2',
  headline: 'No outside network interface was found, so nothing was asked.',
  vantages: [],
  ports: [],
  notes: ['This machine has no packet rules: nothing in the kernel filters traffic.', 'The snapshot has no network interfaces and their addresses.', 'The snapshot has no IPv4 routes.', 'The snapshot has no forwarding settings.'],
  counts: none,
  caveat: CAVEAT,
}

const hanging: Cell = {
  vantage: 'internet',
  from: 'anyone',
  src: '198.51.100.7',
  dst: '203.0.113.10',
  class: 'undecided',
  possible: ['open', 'filtered'],
  why: 'The nftables packet rules could not be read: nft needs root.',
  steps: [
    { kind: 'route', hook: 'route', effect: 'for this machine: 203.0.113.10 is one of its own addresses' },
    { kind: 'deliver', hook: 'deliver', effect: 'a program is listening on 0.0.0.0:22', decisive: true },
  ],
  unknowns: ['The nftables packet rules could not be read: nft needs root.'],
}

const undecidedPort: Port = {
  proto: 'tcp',
  port: 22,
  finding: 'undecided',
  severity: 'unknown',
  title: 'Not decided.',
  reach: 'not known',
  why: 'The nftables packet rules could not be read: nft needs root.',
  views: [{ vantage: 'internet', state: 'undecided' }],
  cells: [hanging],
}

/** Read without root: rule sources that exist and could not be read, and a port left undecided. */
export const notRead: Report = {
  host: 'shop-2',
  headline: 'The firewall rules could not be read, so nothing is decided.',
  detail: 'The kernel shows them to root only. Run it again with sudo.',
  vantages: [internet],
  ports: [undecidedPort],
  unread: ['The nftables packet rules could not be read: nft needs root.', 'The IPv6 packet rules (ip6tables) could not be read: ip6tables-save needs root.'],
  notes: ['The ufw settings could not be read: ufw needs root.'],
  counts: { ...none, undecided: 1 },
  caveat: CAVEAT,
}

/** No firewall tool: there is no list to hold the rules against. */
export const noTool: Report = {
  host: 'edge-2',
  headline: '1 port can be reached from outside.',
  vantages: [internet, { id: 'lan:lan0', label: 'the local network on lan0 (192.0.2.0/24)', short: 'LAN lan0', iface: 'lan0', scope: 'lan' }],
  ports: [
    {
      proto: 'udp',
      port: 51820,
      finding: 'open',
      severity: 'info',
      title: 'Reachable from the internet.',
      service: 'wireguard',
      reach: 'the internet',
      views: [
        { vantage: 'internet', state: 'open' },
        { vantage: 'lan:lan0', state: 'stopped' },
      ],
      cells: [
        {
          vantage: 'internet',
          from: 'anyone',
          src: '198.51.100.7',
          dst: '203.0.113.20',
          class: 'open',
          why: 'Accepted by a rule in chain input of table inet filter.',
          deciding: { kind: 'rule', hook: 'input', family: 'inet', table: 'filter', chain: 'input', rule: 'udp dport 51820 accept', effect: 'accept' },
          steps: [
            { kind: 'route', hook: 'route', effect: 'for this machine: 203.0.113.20 is one of its own addresses' },
            { kind: 'rule', hook: 'input', family: 'inet', table: 'filter', chain: 'input', rule: 'udp dport 51820 accept', effect: 'accept' },
            { kind: 'deliver', hook: 'deliver', effect: 'wireguard is listening on 0.0.0.0:51820', decisive: true },
          ],
        },
      ],
    },
  ],
  counts: { ...none, reachable: 1 },
  caveat: CAVEAT,
}
