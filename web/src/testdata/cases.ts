// Small reports for the states the samples do not reach. Every address is a documentation address.
import type { Cell, Port, Report, Step } from '../types'

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

export const SENDERS_CUT = 'The rules tell more groups of senders apart than the scan asks about from one place: it asked about 1024 of them, and the senders beyond those were not asked.'

/**
 * A scan that stopped at its ceiling of senders: nobody that was asked gets through to sshd, and
 * the report does not rule out that somebody else does. One port did turn out reachable.
 */
export const pastCeiling: Report = {
  host: 'box',
  headline: 'At least 1 port can be reached from outside.',
  detail: 'Not every sender was asked. 1 more port could not be decided.',
  vantages: [internet, { id: 'lan:eth0', label: 'the local network on eth0 (203.0.113.0/24)', short: 'LAN eth0', iface: 'eth0', scope: 'lan' }],
  ports: [
    {
      proto: 'tcp',
      port: 22,
      finding: 'undecided',
      severity: 'unknown',
      title: 'No sender that was asked gets through, and not every sender was asked.',
      service: 'sshd',
      reach: 'nobody that was asked',
      why: SENDERS_CUT,
      views: [
        { vantage: 'internet', state: 'undecided' },
        { vantage: 'lan:eth0', state: 'stopped' },
      ],
      cells: [
        {
          vantage: 'internet',
          from: 'anyone',
          src: '198.51.100.7',
          dst: '203.0.113.10',
          class: 'filtered',
          why: 'No rule lets it in: chain INPUT ends with policy drop.',
          steps: [
            { kind: 'route', hook: 'route', effect: 'for this machine: 203.0.113.10 is one of its own addresses' },
            { kind: 'policy', hook: 'input', family: 'ip', table: 'filter', chain: 'INPUT', effect: 'policy drop: no rule let it through', decisive: true },
          ],
        },
      ],
    },
    {
      proto: 'tcp',
      port: 8080,
      finding: 'limited',
      severity: 'info',
      title: 'Reachable from at least 10.0.0.1, 10.0.0.17, 10.0.0.33 and 1020 more.',
      service: 'nginx',
      reach: 'at least 10.0.0.1, 10.0.0.17, 10.0.0.33 and 1020 more',
      why: 'Accepted by a rule in chain INPUT of table filter.',
      views: [
        { vantage: 'internet', state: 'some', note: 'at least 10.0.0.1, 10.0.0.17, 10.0.0.33 and 1020 more' },
        { vantage: 'lan:eth0', state: 'stopped' },
      ],
      cells: [
        {
          vantage: 'internet',
          from: '10.0.0.1',
          src: '10.0.0.1',
          dst: '203.0.113.10',
          class: 'open',
          why: 'Accepted by a rule in chain INPUT of table filter.',
          steps: [{ kind: 'route', hook: 'route', effect: 'for this machine: 203.0.113.10 is one of its own addresses' }],
        },
        {
          vantage: 'internet',
          from: '10.0.0.17',
          src: '10.0.0.17',
          dst: '203.0.113.10',
          class: 'open',
          why: 'Accepted by a rule in chain INPUT of table filter.',
          steps: [{ kind: 'route', hook: 'route', effect: 'for this machine: 203.0.113.10 is one of its own addresses' }],
        },
      ],
    },
  ],
  partial: [SENDERS_CUT],
  counts: { ...none, reachable: 1, undecided: 1 },
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

/** A chain that packets pass and the engine does not follow, as the report lists it. */
export const INGRESS = 'The chain ingress of table netdev early acts on packets as they pass eth0, underneath the bridge, bond or VLAN interface they arrive on, where seaward does not follow them.'
export const BRIDGE = 'The chain pre of table bridge b acts on frames as they arrive through a bridge, before the packet path seaward follows.'
/** The same reason as a packet carries it: no capital, no full stop. */
const loose = (said: string): string => said.charAt(0).toLowerCase() + said.slice(1, -1)
const MAY_DROP = 'A chain that was not followed may drop it instead.'

const toSelf4: Step = { kind: 'route', hook: 'route', effect: 'for this machine: 203.0.113.10 is one of its own addresses' }
const toSelf6: Step = { kind: 'route', hook: 'route', effect: 'for this machine: 2001:db8::10 is one of its own addresses' }
const accept: Step = { kind: 'rule', hook: 'input', family: 'inet', table: 'filter', chain: 'input', rule: 'tcp dport 22 accept', effect: 'accept' }
const refuse: Step = { kind: 'rule', hook: 'input', family: 'inet', table: 'filter', chain: 'input', rule: 'tcp dport 113 reject with tcp reset', effect: 'reject: the sender is told', decisive: true }
const from4 = { vantage: 'internet', from: 'anyone', src: '198.51.100.7', dst: '203.0.113.10' } as const
const from6 = { vantage: 'internet', from: 'anyone', src: '2001:db8:99::7', dst: '2001:db8::10', ipv6: true } as const

/**
 * A machine behind a bridge, with a chain underneath it that is not followed. Port 22 gets in over
 * IPv4 unless that chain drops it, and reaches nothing over IPv6 either way; port 113 is refused
 * either way, so it counts as stopped.
 */
export const notFollowed: Report = {
  host: 'gate-1',
  headline: '1 port could not be decided.',
  detail: 'No other port can be reached from outside.',
  vantages: [internet],
  ports: [
    {
      proto: 'tcp',
      port: 22,
      finding: 'undecided',
      severity: 'unknown',
      title: 'Not decided.',
      service: 'sshd',
      reach: 'not known',
      why: `Accepted by a rule in chain input of table inet filter. ${MAY_DROP}`,
      views: [{ vantage: 'internet', state: 'undecided' }],
      cells: [
        {
          ...from4,
          class: 'undecided',
          possible: ['open', 'filtered'],
          otherwise: 'open',
          why: `Accepted by a rule in chain input of table inet filter. ${MAY_DROP}`,
          deciding: accept,
          steps: [toSelf4, accept, { kind: 'deliver', hook: 'deliver', effect: 'sshd is listening on 0.0.0.0:22', decisive: true }],
          unknowns: [loose(INGRESS)],
        },
        {
          ...from6,
          class: 'undecided',
          possible: ['closed', 'filtered'],
          otherwise: 'closed',
          why: `The firewall lets it through, but nothing is listening on tcp port 22 at 2001:db8::10. ${MAY_DROP}`,
          deciding: accept,
          steps: [toSelf6, accept, { kind: 'deliver', hook: 'deliver', effect: 'nothing is listening on tcp port 22 at 2001:db8::10', decisive: true }],
          unknowns: [loose(INGRESS)],
        },
      ],
    },
    {
      proto: 'tcp',
      port: 113,
      finding: 'blocked',
      severity: 'ok',
      title: 'Stopped by the firewall.',
      service: 'oidentd',
      reach: 'nobody',
      why: `Refused by a rule in chain input of table inet filter. ${MAY_DROP}`,
      deciding: refuse,
      views: [{ vantage: 'internet', state: 'stopped' }],
      cells: [
        {
          ...from4,
          class: 'undecided',
          possible: ['rejected', 'filtered'],
          otherwise: 'rejected',
          why: `Refused by a rule in chain input of table inet filter. ${MAY_DROP}`,
          deciding: refuse,
          steps: [toSelf4, refuse],
          unknowns: [loose(INGRESS)],
        },
      ],
    },
  ],
  unfollowed: [INGRESS],
  counts: { ...none, stopped: 1, undecided: 1 },
  caveat: CAVEAT,
}

const HOUR = 'The meta hour match depends on the time of day or the date, which seaward does not model.'

/** A port left undecided for a reason of its own, which no list in the fine print gives. */
export const ownReason: Report = {
  host: 'gate-2',
  headline: '1 port could not be decided.',
  vantages: [internet],
  ports: [
    {
      proto: 'tcp',
      port: 22,
      finding: 'undecided',
      severity: 'unknown',
      title: 'Not decided.',
      service: 'sshd',
      reach: 'not known',
      why: HOUR,
      views: [{ vantage: 'internet', state: 'undecided' }],
      cells: [
        {
          ...from4,
          class: 'undecided',
          possible: ['open', 'filtered'],
          why: HOUR,
          steps: [toSelf4, { ...accept, rule: 'tcp dport 22 meta hour "09:00" accept' }, { kind: 'deliver', hook: 'deliver', effect: 'sshd is listening on 0.0.0.0:22', decisive: true }],
          unknowns: [loose(HOUR)],
        },
      ],
    },
  ],
  counts: { ...none, undecided: 1 },
  caveat: CAVEAT,
}

const early: Step = { kind: 'rule', hook: 'ingress', family: 'netdev', table: 'early', chain: 'ingress', rule: 'tcp dport 80 drop', effect: 'drop', decisive: true }

/** A port stopped as the packet arrives on the interface, before any routing: the ingress hook. */
export const atIngress: Report = {
  host: 'gate-3',
  headline: 'Nothing can be reached from outside.',
  vantages: [internet],
  ports: [
    {
      proto: 'tcp',
      port: 80,
      finding: 'blocked',
      severity: 'ok',
      title: 'Stopped by the firewall.',
      service: 'nginx',
      reach: 'nobody',
      why: 'Dropped by a rule in chain ingress of table netdev early.',
      deciding: early,
      views: [{ vantage: 'internet', state: 'stopped' }],
      cells: [{ ...from4, class: 'filtered', why: 'Dropped by a rule in chain ingress of table netdev early.', deciding: early, steps: [early] }],
    },
  ],
  counts: { ...none, stopped: 1 },
  caveat: CAVEAT,
}

/** Rules far too long for one line: options one after another, a long remark, and one word longer than any line. */
export const LONG_JUMP =
  '-A INPUT -d 203.0.113.10/32 -i eth0 -p tcp -m multiport --dports 25,465,587,993,995,4190 -m conntrack --ctstate NEW -m comment --comment "mail for the office and both relays, added for the migration and never taken out again" -j MAIL-IN'
export const LONG_WORD = '-A MAIL-IN -s 198.51.100.0/24 -m comment --comment "https://tickets.example/ops/firewall/2026/allow-the-office-network-through-to-every-mail-port" -j ACCEPT'
export const LONG_NFT = 'ip saddr { 198.51.100.0/24, 192.0.2.25, 203.0.113.64/26 } tcp dport { 25, 465, 587, 993, 995, 4190 } ct state new accept comment "mail for the office and both relays"'

const mailIn: Step = { kind: 'jump', hook: 'input', family: 'ip', table: 'filter', chain: 'INPUT', rule: LONG_JUMP, effect: 'to chain MAIL-IN' }
const office: Step = { kind: 'rule', hook: 'input', family: 'ip', table: 'filter', chain: 'MAIL-IN', rule: LONG_WORD, effect: 'accept' }
const office6: Step = { kind: 'rule', hook: 'input', family: 'inet', table: 'filter', chain: 'input', rule: LONG_NFT, effect: 'accept' }

/** A mail relay whose rules were written by hand over the years. */
export const longRules: Report = {
  host: 'relay-2',
  headline: '2 ports can be reached from outside.',
  vantages: [internet],
  ports: [
    {
      proto: 'tcp',
      port: 587,
      finding: 'limited',
      severity: 'info',
      title: 'Reachable from 198.51.100.0/24 only.',
      service: 'smtpd',
      reach: '198.51.100.0/24 only',
      why: 'Accepted by a rule in chain MAIL-IN of table filter.',
      deciding: office,
      views: [{ vantage: 'internet', state: 'some', note: '198.51.100.0/24 only' }],
      cells: [
        {
          vantage: 'internet',
          from: '198.51.100.0/24',
          src: '198.51.100.7',
          dst: '203.0.113.10',
          class: 'open',
          why: 'Accepted by a rule in chain MAIL-IN of table filter.',
          deciding: office,
          steps: [toSelf4, mailIn, office, { kind: 'deliver', hook: 'deliver', effect: 'smtpd is listening on 0.0.0.0:587', decisive: true }],
        },
      ],
    },
    {
      proto: 'tcp',
      port: 993,
      finding: 'limited',
      severity: 'info',
      title: 'Reachable from 198.51.100.0/24 only.',
      service: 'imapd',
      reach: '198.51.100.0/24 only',
      why: 'Accepted by a rule in chain input of table inet filter.',
      deciding: office6,
      views: [{ vantage: 'internet', state: 'some', note: '198.51.100.0/24 only' }],
      cells: [
        {
          vantage: 'internet',
          from: '198.51.100.0/24',
          src: '198.51.100.7',
          dst: '203.0.113.10',
          class: 'open',
          why: 'Accepted by a rule in chain input of table inet filter.',
          deciding: office6,
          steps: [toSelf4, office6, { kind: 'deliver', hook: 'deliver', effect: 'imapd is listening on 0.0.0.0:993', decisive: true }],
        },
      ],
    },
  ],
  counts: { ...none, reachable: 2 },
  caveat: CAVEAT,
}
