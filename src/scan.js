/**
 * TCP probing and the ARP table reader.
 *
 * netpeek does not use ICMP: raw sockets need root or Administrator, and a
 * ping-based scanner is wrong on any host with a firewall that drops echo
 * requests. Instead "is this address alive?" is answered by trying a small set
 * of TCP ports — a device that answers on any of them is certainly up.
 *
 * Every probe is a real connect() with a timeout, run through a bounded pool so
 * a /24 scan does not open 254 sockets at once.
 */

import net from 'node:net';
import { spawn } from 'node:child_process';

/** Ports worth trying when the question is only "is anything there?". */
export const COMMON_PORTS = [
  { port: 22, service: 'ssh' },
  { port: 23, service: 'telnet' },
  { port: 53, service: 'dns' },
  { port: 80, service: 'http' },
  { port: 135, service: 'msrpc' },
  { port: 139, service: 'netbios' },
  { port: 443, service: 'https' },
  { port: 445, service: 'smb' },
  { port: 3389, service: 'rdp' },
  { port: 5000, service: 'upnp' },
  { port: 8080, service: 'http-alt' },
];

/** Well-known service names, used to label whatever the user asked to scan. */
const SERVICE_NAMES = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  135: 'msrpc',
  139: 'netbios',
  143: 'imap',
  443: 'https',
  445: 'smb',
  587: 'smtp-submission',
  631: 'ipp',
  993: 'imaps',
  995: 'pop3s',
  1433: 'mssql',
  1521: 'oracle',
  2049: 'nfs',
  2375: 'docker',
  3000: 'dev-http',
  3306: 'mysql',
  3389: 'rdp',
  5000: 'upnp',
  5432: 'postgres',
  5900: 'vnc',
  6379: 'redis',
  8000: 'http-alt',
  8080: 'http-alt',
  8443: 'https-alt',
  9000: 'http-alt',
  9090: 'prometheus',
  27017: 'mongodb',
};

/** Name for a port number, or null when it is not a well-known one. */
export function serviceName(port) {
  return SERVICE_NAMES[port] ?? null;
}

/**
 * Probe one TCP endpoint.
 *
 * Resolves (never rejects) with a result object, because a refused connection
 * is a normal answer, not an error:
 *   { host, port, status: 'open'|'closed'|'timeout'|'unreachable', ms, error }
 *
 * `closed` and `timeout` are kept apart on purpose. A refused connection proves
 * something is at that address and had no listener; a timeout proves nothing at
 * all (the packet may simply have been dropped), so a live-host decision must
 * only trust `open`.
 */
export function probePort(host, port, { timeout = 400, family = 4 } = {}) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    let settled = false;
    const socket = new net.Socket();

    const finish = (status, error = null) => {
      if (settled) return;
      settled = true;
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      socket.destroy();
      resolve({ host, port, status, ms: Math.round(ms * 10) / 10, error });
    };

    socket.setTimeout(timeout);
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('timeout'));
    socket.once('error', (error) => {
      const code = error.code;
      if (code === 'ECONNREFUSED' || code === 'ECONNRESET') finish('closed', code);
      else if (code === 'ETIMEDOUT') finish('timeout', code);
      else if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') finish('unreachable', code);
      else finish('closed', code);
    });

    try {
      socket.connect({ host, port, family });
    } catch (error) {
      finish('closed', error.code ?? 'EINVAL');
    }
  });
}

/**
 * Run tasks with a bounded number in flight, preserving input order.
 *
 * Same contract as the pool in the sibling spacehog project: order in equals
 * order out, a rejected task does not abort the run, and the peak concurrency
 * never exceeds the limit.
 */
export async function mapPool(items, limit, worker) {
  const results = new Array(items.length);
  if (items.length === 0) return results;
  const size = Math.max(1, Math.min(limit, items.length));
  let next = 0;

  const run = async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      try {
        results[index] = await worker(items[index], index);
      } catch (error) {
        results[index] = { error: error?.message ?? String(error) };
      }
    }
  };

  await Promise.all(Array.from({ length: size }, run));
  return results;
}

/**
 * Nudge the kernel into resolving addresses, so the ARP table has entries.
 *
 * A Windows ARP entry expires in a couple of minutes, and a machine that has
 * only been *listened to* never creates one at all — so right after a scan the
 * table is often empty and every device shows as "unknown". Sending one UDP
 * datagram to a port nothing is listening on has no protocol side effect, but
 * it forces the kernel to resolve the link-layer address first. That single
 * datagram is what turns "unknown vendor" into a real MAC.
 *
 * Deliberately not ICMP: that needs raw sockets and Administrator rights.
 */
export async function primeArpTable(hosts, { settle = 250 } = {}) {
  const dgram = await import('node:dgram');
  const socket = dgram.createSocket('udp4');
  const payload = Buffer.from([0]);
  for (const host of hosts) {
    try {
      socket.send(payload, 9, host, () => {});
    } catch {
      // A host that cannot even be addressed is not an error here
    }
  }
  await new Promise((resolve) => setTimeout(resolve, settle));
  try {
    socket.close();
  } catch {
    /* already closed */
  }
}

/**
 * Read the OS ARP table: the address-to-MAC mapping the machine already has.
 *
 * This is free information — every host the machine has talked to recently is
 * already there — and it is what turns "something answered on 192.168.1.7" into
 * "a TP-Link device is at 192.168.1.7". The formats differ per platform:
 *
 *   Windows  arp -a      ->  192.168.1.1    00-11-22-33-44-55   dynamic
 *   macOS    arp -an     ->  ? (192.168.1.1) at 0:11:22:33:44:55 on en0
 *   Linux    /proc/net/arp (no subprocess at all)
 *
 * Failure is not fatal: an empty map means unknown vendors, not a broken scan.
 */
export function readArpTable({ platform = process.platform, readFile = null, run = null } = {}) {
  if (platform === 'linux' && readFile) {
    try {
      const text = readFile('/proc/net/arp', 'utf8');
      return parseProcNetArp(text);
    } catch {
      return new Map();
    }
  }
  if (platform === 'win32' && run) {
    return parseWindowsArp(run('arp', ['-a']));
  }
  if ((platform === 'darwin' || platform === 'linux') && run) {
    return parseBsdArp(run('arp', ['-an']));
  }
  return new Map();
}

/** Run a command and return its stdout, or '' when it fails or does not exist. */
export function defaultRunner(command, args) {
  return new Promise((resolve) => {
    let child;
    try {
      const isWindows = process.platform === 'win32';
      if (isWindows) {
        // `arp` prints in the OEM code page, which is GBK on a Chinese install;
        // Node would decode those bytes as UTF-8 and produce mojibake for the
        // header and the type column. `chcp 65001` switches the console to
        // UTF-8 for this child only.
        //
        // The argument vector matters: spawn('cmd', []) with no /c opens an
        // interactive shell that never exits, which hangs the caller forever.
        // `/d /s /c` with the command as one argument is the non-interactive
        // form, and the argument is quoted because the command contains spaces.
        child = spawn('cmd', ['/d', '/s', '/c', `chcp 65001>nul && ${command} ${args.join(' ')}`], {
          windowsHide: true,
        });
      } else {
        child = spawn(command, args, { windowsHide: true });
      }
    } catch {
      resolve('');
      return;
    }
    // Keep the bytes together: a multi-byte character can straddle two chunks,
    // and concatenating per-chunk strings would corrupt it.
    const chunks = [];
    child.stdout?.on('data', (chunk) => chunks.push(chunk));
    child.once('error', () => resolve(''));
    child.once('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

/** Async wrapper around readArpTable that runs the platform command for real. */
export async function arpTable({ platform = process.platform } = {}) {
  const fs = await import('node:fs');
  if (platform === 'linux') {
    const direct = readArpTable({ platform, readFile: fs.readFileSync });
    if (direct.size > 0) return direct;
  }
  const command = platform === 'win32' ? '-a' : '-an';
  const output = await defaultRunner(platform === 'win32' ? 'arp' : 'arp', [command]);
  if (platform === 'win32') return parseWindowsArp(output);
  return parseBsdArp(output);
}

/**
 * Parse Windows `arp -a` output.
 *
 * Matched purely on the shape of a row — an IPv4 literal followed by six
 * dash-separated hex pairs — with no reference to the type column. The first
 * version required the literal words "static" or "dynamic", which silently
 * discarded every row on a localized Windows: a Chinese install prints
 * "动态", so the table came back empty and every device was reported as an
 * unknown vendor with no hint that anything had gone wrong.
 *
 * A language-independent match is both more robust and simpler.
 */
export function parseWindowsArp(text) {
  const table = new Map();
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b/.exec(line);
    if (!match) continue;
    const [, ip, mac] = match;
    // An all-zero MAC is a placeholder for an unresolved entry, not a device
    if (/^(00-){5}00$/.test(mac)) continue;
    table.set(ip, mac.replace(/-/g, ':').toUpperCase());
  }
  return table;
}

/** Parse BSD/macOS `arp -an` output, including the Windows-style fallback. */
export function parseBsdArp(text) {
  const table = new Map();
  for (const line of String(text).split(/\r?\n/)) {
    // ? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
    const bsd = /\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]+)/.exec(line);
    if (bsd) {
      const mac = normalizeShortMac(bsd[2]);
      if (mac) table.set(bsd[1], mac);
      continue;
    }
    // Some builds print the same layout as Windows
    const win = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})/i.exec(line);
    if (win) {
      const mac = normalizeShortMac(win[2]);
      if (mac) table.set(win[1], mac);
    }
  }
  return table;
}

/** Parse /proc/net/arp (Linux). */
export function parseProcNetArp(text) {
  const table = new Map();
  const lines = String(text).split(/\r?\n/);
  for (const line of lines.slice(1)) {
    // IP address  HW type  Flags  HW address  Mask  Device
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;
    const [ip, , flags, mac] = parts;
    // Flags 0x0 means the entry is incomplete — there is no usable MAC yet
    if (flags === '0x0') continue;
    const normalized = normalizeShortMac(mac);
    if (normalized) table.set(ip, normalized);
  }
  return table;
}

/**
 * Normalise a MAC that may use one- or two-digit groups, or Cisco's 4-4-4 dot
 * form (`aabb.ccdd.eeff`, which is what Windows prints in some locales and what
 * switches show in `show mac address-table`).
 *
 * Returns null for anything that is not twelve hex digits after cleaning, so an
 * incomplete ARP entry is reported as unknown rather than as a fake device.
 */
export function normalizeShortMac(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (raw === '' || raw.includes('<') || raw.includes('(incomplete)')) return null;

  // 4-4-4 with dots is unambiguous; check it before the general split so
  // "aabb.ccdd.eeff" is not mistaken for three invalid groups.
  const dotted = /^([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})$/.exec(raw);
  if (dotted) {
    return `${dotted[1]}${dotted[2]}${dotted[3]}`.match(/.{2}/g).join(':').toUpperCase();
  }

  const groups = raw.split(/[:-]/).filter(Boolean);
  if (groups.length === 0) return null;
  if (groups.some((g) => !/^[0-9a-f]{1,2}$/.test(g))) return null;
  const hex = groups.map((g) => g.padStart(2, '0')).join('');
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':').toUpperCase();
}
