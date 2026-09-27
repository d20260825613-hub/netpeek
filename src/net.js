/**
 * Address and interface helpers.
 *
 * Everything here works on strings and plain objects: no sockets, no promises,
 * no process state. That keeps the interesting half of netpeek (which address
 * is worth probing, what the answer means) testable without a network.
 */

/** Dotted-quad string to a 32-bit unsigned integer. Returns null when invalid. */
export function ipToInt(ip) {
  // No trimming: " 1.2.3.4" is not an IPv4 literal, and silently accepting it
  // would hide a quoting bug in whatever produced the string.
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

/** 32-bit unsigned integer back to a dotted quad. */
export function intToIp(value) {
  const n = value >>> 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** True when the string is a valid IPv4 literal. */
export function isIPv4(value) {
  return ipToInt(value) !== null;
}

/**
 * Prefix length to a netmask integer. Returns null outside 0..32.
 */
export function prefixToInt(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

/**
 * Parse `192.168.1.10/24`, `192.168.1.10`, or a bare `/24`.
 *
 * A bare prefix with no address is allowed because the useful case is "scan my
 * own subnet": the caller fills the address in from the chosen interface.
 * Returns { address, prefix, error } — error is a string when unparseable.
 */
export function parseTarget(input) {
  const text = String(input ?? '').trim();
  if (text === '') return { address: null, prefix: null, error: 'empty target' };

  const slash = text.indexOf('/');
  if (slash === -1) {
    if (!isIPv4(text)) return { address: null, prefix: null, error: `not an IPv4 address: ${text}` };
    return { address: text, prefix: null, error: null };
  }

  const address = text.slice(0, slash);
  const prefixText = text.slice(slash + 1);
  if (!/^\d{1,2}$/.test(prefixText)) {
    return { address: null, prefix: null, error: `not a prefix length: /${prefixText}` };
  }
  const prefix = Number(prefixText);
  if (prefix > 32) return { address: null, prefix: null, error: `prefix out of range: /${prefix}` };
  if (address !== '' && !isIPv4(address)) {
    return { address: null, prefix: null, error: `not an IPv4 address: ${address}` };
  }
  return { address: address === '' ? null : address, prefix, error: null };
}

/** The network and broadcast addresses for an address + prefix. */
export function networkBounds(address, prefix) {
  const ip = ipToInt(address);
  const mask = prefixToInt(prefix);
  if (ip === null || mask === null) return null;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return { network, broadcast, networkIp: intToIp(network), broadcastIp: intToIp(broadcast) };
}

/**
 * Expand an address + prefix into the list of probeable host addresses.
 *
 * The network and broadcast addresses are excluded (they are not assignable on
 * a normal subnet). `/31` and `/32` are kept whole: RFC 3021 point-to-point
 * links use both addresses, and a /32 is a single host by definition.
 *
 * `total` is the number of *usable* addresses — what a scan is supposed to
 * cover — not the size of the subnet. The two differ by two on any prefix up to
 * /30, and reporting the subnet size would make progress output and the
 * truncation note wrong.
 *
 * `limit` guards against a typo turning into 16 million probes; the caller
 * decides what to do when the range is larger.
 */
export function hostsInRange(address, prefix, { limit = 4096 } = {}) {
  if (!isIPv4(address)) return { hosts: [], total: 0, truncated: false, error: `not an IPv4 address: ${address}` };
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return { hosts: [], total: 0, truncated: false, error: `bad prefix: /${prefix}` };
  }

  const bounds = networkBounds(address, prefix);
  const { network, broadcast } = bounds;

  // /31 and /32 are special: every address in them is assigned to a host, so
  // the network and broadcast reservations do not apply. total therefore counts
  // all of them rather than all-minus-two.
  const pointToPoint = prefix >= 31;
  const total = pointToPoint ? broadcast - network + 1 : Math.max(0, broadcast - network - 1);

  let first = network;
  let last = broadcast;
  if (!pointToPoint) {
    first = network + 1;
    last = broadcast - 1;
  }

  const usable = last - first + 1;
  if (usable <= 0) return { hosts: [], total: 0, truncated: false, error: null };

  if (usable > limit) {
    const hosts = [];
    for (let i = 0; i < limit; i += 1) hosts.push(intToIp(first + i));
    return { hosts, total: usable, truncated: true, error: null };
  }

  const hosts = new Array(usable);
  for (let i = 0; i < usable; i += 1) hosts[i] = intToIp(first + i);
  return { hosts, total, truncated: false, error: null };
}

/**
 * Pick the interface to scan when the user did not name one.
 *
 * Candidates are scored rather than taken in enumeration order. Enumerating in
 * order looks fine until you meet a machine with a VirtualBox or Hyper-V
 * adapter: `os.networkInterfaces()` lists those first, so the "default" scan
 * silently probed the 192.168.56.0/24 host-only network instead of the real
 * Wi-Fi LAN. Scoring prefers a private address, penalises names that are known
 * virtual switches, and mildly prefers Wi-Fi/Ethernet over anything else.
 *
 * The scoring is heuristic by design. It is one function, it is tested, and the
 * answer is always shown in the report, so a wrong guess is visible and
 * correctable with an explicit target.
 */
export function pickInterface(interfaces) {
  const candidates = [];
  for (const [name, addresses] of Object.entries(interfaces ?? {})) {
    for (const address of addresses ?? []) {
      if (address.family !== 'IPv4' && address.family !== 4) continue;
      if (address.internal) continue;
      candidates.push({
        name,
        address: address.address,
        netmask: address.netmask ?? null,
        mac: address.mac ?? null,
        cidr: address.cidr ?? null,
      });
    }
  }
  if (candidates.length === 0) return null;

  const scored = candidates.map((candidate) => ({ candidate, score: scoreInterface(candidate) }));
  scored.sort((a, b) => b.score - a.score);
  return scored[0].candidate;
}

/** Interface names that indicate a virtual switch rather than the real LAN. */
const VIRTUAL_NAME_PATTERN =
  /virtual|vmware|vbox|hyper-?v|vethernet|docker|br-|virbr|tap|tun|loopback|wsl|tailscale|zerotier|hamachi|radmin|npcap|bluetooth|teredo|isatap|6to4/i;

/** Private ranges used by hypervisor host-only networks rather than a LAN. */
const HOST_ONLY_RANGES = ['192.168.56.', '192.168.99.', '192.168.174.', '192.168.240.', '192.168.137.'];

/**
 * Higher is better. Exported because a surprising default is easier to explain
 * with the number in hand than with prose.
 */
export function scoreInterface(candidate) {
  const ip = ipToInt(candidate.address);
  if (ip === null) return -1000;

  let score = 0;
  const first = (ip >>> 24) & 255;
  const second = (ip >>> 16) & 255;

  if (first === 10) score += 40;
  else if (first === 172 && second >= 16 && second <= 31) score += 40;
  else if (first === 192 && second === 168) score += 40;
  else if (first === 169 && second === 254) score -= 60; // APIPA: no DHCP lease
  else score -= 20; // public address: a corporate LAN, but usually not "my LAN"

  if (HOST_ONLY_RANGES.some((prefix) => candidate.address.startsWith(prefix))) score -= 50;
  if (VIRTUAL_NAME_PATTERN.test(candidate.name)) score -= 40;
  if (/^wlan|^wi-?fi|^wireless/i.test(candidate.name)) score += 15;
  else if (/^eth|^en\d|^ethernet|^本地连接|^以太网/i.test(candidate.name)) score += 10;

  return score;
}

/** Netmask string to prefix length, e.g. 255.255.255.0 -> 24. */
export function netmaskToPrefix(netmask) {
  const mask = ipToInt(netmask);
  if (mask === null) return null;
  let bits = 0;
  for (let i = 31; i >= 0; i -= 1) {
    if ((mask >>> i) & 1) bits += 1;
    else break;
  }
  // A non-contiguous mask (255.0.255.0) is not a real netmask
  if (prefixToInt(bits) !== mask) return null;
  return bits;
}

/**
 * Derive the prefix for an interface, preferring an explicit CIDR string.
 *
 * os.networkInterfaces() reports `cidr` on every platform this supports, but it
 * is not guaranteed by the docs, so the netmask is the fallback.
 */
export function prefixForAddress(entry) {
  if (entry.cidr) {
    const parsed = parseTarget(entry.cidr);
    if (parsed.prefix !== null) return parsed.prefix;
  }
  if (entry.netmask) {
    const prefix = netmaskToPrefix(entry.netmask);
    if (prefix !== null) return prefix;
  }
  return null;
}
