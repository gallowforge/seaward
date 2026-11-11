// The report, exactly as the engine writes it: internal/scan/report.go and
// internal/engine/api.go. Keep the names and the optional marks in step with those two files.

/** One thing that happened to a packet on its way (engine.Step). */
export interface Step {
  kind: StepKind
  /** "prerouting", "input", "forward", "postrouting"; "route" and "deliver" for those two kinds. */
  hook?: string
  /** The table family: "ip", "ip6", "inet". */
  family?: string
  table?: string
  chain?: string
  /** The rule as its owner prints it. */
  rule?: string
  /** A few plain words: "accept", "to chain DOCKER", "destination becomes 172.17.0.2:80". */
  effect: string
  /** The step that settled the result. */
  decisive?: boolean
}

export type StepKind = 'rule' | 'jump' | 'policy' | 'route' | 'deliver'

/** Everything Seaward says about one machine. */
export interface Report {
  host: string
  headline: string
  detail?: string
  frontend?: Frontend
  vantages: Vantage[]
  ports: Port[]
  /** Rule sources that exist on the machine and could not be read. */
  unread?: string[]
  notes?: string[]
  counts: Counts
  /** The limit every report has, in one sentence. */
  caveat: string
}

export interface Counts {
  /** exposed, open, limited */
  reachable: number
  exposed: number
  /** blocked, shadowed */
  stopped: number
  /** local, closed, dead */
  quiet: number
  undecided: number
}

/** The firewall manager and what it says it allows. */
export interface Frontend {
  tool: string
  default: string
  allows: string[]
}

/** One place a packet can come from. */
export interface Vantage {
  /** "internet", "lan:eth0", "vpn:wg0" */
  id: string
  /** "the internet", "the local network on eth0 (192.0.2.0/24)" */
  label: string
  /** "internet", "LAN eth0" */
  short: string
  iface: string
  scope: 'world' | 'lan' | 'vpn' | (string & {})
}

/** The findings, most serious first. */
export type Finding = 'exposed' | 'open' | 'limited' | 'undecided' | 'shadowed' | 'dead' | 'blocked' | 'closed' | 'local'

export type Severity = 'high' | 'medium' | 'unknown' | 'info' | 'low' | 'ok'

/** One port and what was found out about it. */
export interface Port {
  proto: string
  port: number
  finding: Finding
  severity: Severity
  title: string
  /** "sshd", "nginx in container web (nginx:1.27)" */
  service?: string
  /** Who gets through: "the internet", "the local network only". */
  reach?: string
  /** What the firewall manager says about it. */
  stated?: string
  why?: string
  /** The rule that sent the packet somewhere else. */
  rewrite?: Step
  /** The rule or policy that settled it. */
  deciding?: Step
  /** The port seen from each place in Report.vantages, in the same order. */
  views: View[]
  cells: Cell[]
}

export type ViewState = 'open' | 'some' | 'stopped' | 'closed' | 'undecided'

/** One port seen from one place. */
export interface View {
  vantage: string
  state: ViewState
  /** "IPv4 only", "198.51.100.0/24 only" */
  note?: string
}

/** How a packet ended (engine.Class). */
export type CellClass = 'open' | 'closed' | 'rejected' | 'filtered' | 'forwarded' | 'undecided'

/** One packet: who sent it, to which address, how it ended and why. */
export interface Cell {
  vantage: string
  /** The senders this packet stands for. */
  from: string
  src: string
  dst: string
  ipv6?: boolean
  class: CellClass
  possible?: string[]
  /** What the firewall manager says about this packet; absent without a manager. */
  allowed?: boolean
  why: string
  rewrite?: Step
  deciding?: Step
  steps: Step[]
  unknowns?: string[]
}

/** What seawardScan answers (cmd/seaward-wasm/main.go). */
export interface Answer {
  ok: boolean
  error?: string
  version: string
  report?: Report
}

/** One line of samples/index.json. */
export interface Sample {
  id: string
  file: string
  title: string
  description: string
}
