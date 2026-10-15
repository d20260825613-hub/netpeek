/**
 * Scan orchestration. Returns data structures; never prints.
 *
 * Kept free of process concerns (no argv, no stdout) so the whole decision
 * layer — which addresses to probe, what counts as alive, how a device is
 * labelled — can be tested without a network and without a terminal.
 */

import os from 'node:os';

import {
  hostsInRange,
  pickInterface,
  prefixForAddress,
  parseTarget,
  isIPv4,
} from './net.js';
import { COMMON_PORTS, arpTable, mapPool, primeArpTable, probePort, serviceName } from './scan.js';
import { isGroupAddress, isLocallyAdministered, normalizeMac, vendorFor } from './mac.js';

export const VERSION = '0.2.0';

/**
 * This machine's own IPv4 addresses, mapped to their interface MAC.
 *
 * An interface never has an ARP entry for itself, so without this a scan would
 * report the machine running it as "unknown (not in ARP table)" — technically
 * true and completely unhelpful.
 */
export function ownAddresses({ interfaces = null } = {}) {
  const table = interfaces ?? os.networkInterfaces();
  const map = new Map();
  for (const [name, addresses] of Object.entries(table)) {
    for (const address of addresses ?? []) {
      if (address.family !== 'IPv4' && address.family !== 4) continue;
      map.set(address.address, { name, mac: normalizeMac(address.mac) });
    }
  }
  return map;
}

/** The default probe set, with service labels attached. */
export function defaultPorts() {
  return COMMON_PORTS.map((p) => ({ ...p }));
}

/**
 * Parse a port list from CLI text: `22`, `22,80,443`, `1-1024`, or a mix.
 * Returns { ports, error } — an error string means nothing was scanned.
 */
export function parsePorts(spec) {
  const text = String(spec ?? '').trim();
  if (text === '') return { ports: [], error: 'empty port list' };

  const ports = new Set();
  for (const chunk of text.split(',')) {
    const piece = chunk.trim();
    if (piece === '') continue;

    const range = /^(\d{1,5})-(\d{1,5})$/.exec(piece);
    if (range) {
      const from = Number(range[1]);
      const to = Number(range[2]);
      if (from < 1 || to > 65535 || from > to) {
        return { ports: [], error: `bad port range: ${piece}` };
      }
      if (to - from > 4096) {
        return { ports: [], error: `port range too wide (${to - from + 1} ports): ${piece}` };
      }
      for (let port = from; port <= to; port += 1) ports.add(port);
      continue;
    }

    if (!/^\d{1,5}$/.test(piece)) return { ports: [], error: `not a port: ${piece}` };
    const port = Number(piece);
    if (port < 1 || port > 65535) return { ports: [], error: `port out of range: ${piece}` };
    ports.add(port);
  }

  if (ports.size === 0) return { ports: [], error: 'no ports given' };
  return {
    ports: [...ports].sort((a, b) => a - b).map((port) => ({ port, service: serviceName(port) })),
    error: null,
  };
}

/**
 * Build the target list for a scan.
 *
 * Returns { hosts, interface, prefix, cidr, total, truncated, error }.
 * An explicit address wins; otherwise the interface with a private IPv4 address
 * is used, because that is the LAN the user means when they run this.
 */
export function resolveTargets({ target = null, interfaces = null, limit = 4096 } = {}) {
  const table = interfaces ?? os.networkInterfaces();

  if (target) {
    const parsed = parseTarget(target);
    if (parsed.error) return { hosts: [], error: parsed.error };

    if (parsed.address === null) {
      // A bare /24: fill the address in from the default interface
      const chosen = pickInterface(table);
      if (!chosen) return { hosts: [], error: 'no external IPv4 interface found' };
      const prefix = parsed.prefix ?? prefixForAddress(chosen) ?? 24;
      const expanded = hostsInRange(chosen.address, prefix, { limit });
      return {
        hosts: expanded.hosts,
        interface: chosen.name,
        address: chosen.address,
        prefix,
        cidr: `${chosen.address}/${prefix}`,
        total: expanded.total,
        truncated: expanded.truncated,
        error: expanded.error,
      };
    }

    const chosen = pickInterface(table);
    const prefix = parsed.prefix ?? (chosen ? prefixForAddress(chosen) : null) ?? 32;
    const expanded = hostsInRange(parsed.address, prefix, { limit });
    return {
      hosts: expanded.hosts,
      interface: chosen?.name ?? null,
      address: parsed.address,
      prefix,
      cidr: `${parsed.address}/${prefix}`,
      total: expanded.total,
      truncated: expanded.truncated,
      error: expanded.error,
    };
  }

  const chosen = pickInterface(table);
  if (!chosen) return { hosts: [], error: 'no external IPv4 interface found' };
  const prefix = prefixForAddress(chosen) ?? 24;
  const expanded = hostsInRange(chosen.address, prefix, { limit });
  return {
    hosts: expanded.hosts,
    interface: chosen.name,
    address: chosen.address,
    prefix,
    cidr: `${chosen.address}/${prefix}`,
    total: expanded.total,
    truncated: expanded.truncated,
    error: expanded.error,
  };
}

/** Describe a device from its MAC address, without overclaiming. */
export function describeDevice(mac) {
  const normalized = normalizeMac(mac);
  if (!normalized) return { mac: null, vendor: null, kind: 'unknown', note: 'not in the ARP table' };

  if (isGroupAddress(normalized)) {
    return { mac: normalized, vendor: null, kind: 'group', note: 'multicast or broadcast address' };
  }

  const vendor = vendorFor(normalized);
  if (vendor) return { mac: normalized, vendor, kind: 'device', note: null };

  if (isLocallyAdministered(normalized)) {
    return {
      mac: normalized,
      vendor: null,
      kind: 'randomised',
      note: 'locally administered address: a virtual adapter or a randomised MAC',
    };
  }

  return { mac: normalized, vendor: null, kind: 'unknown-vendor', note: 'OUI not in the built-in table' };
}

/**
 * Scan a range of addresses for open TCP ports.
 *
 * A host counts as alive when at least one probed port is *open*. A refused
 * connection is deliberately not enough: it proves something answered, but on a
 * routed network it can also be the router, and reporting the router as every
 * host would be worse than missing a silent device.
 *
 * `stopAtFirstOpen` trades port detail for speed, which is the right default
 * when the question is "what is on my network" rather than "what is on this
 * particular box".
 *
 * An aborted scan (`signal`) returns `aborted: true` and reports how many
 * addresses were actually probed, so a partial result can never be mistaken for
 * a complete one.
 */
export async function discover({
  target = null,
  interfaces = null,
  ports = defaultPorts(),
  concurrency = 128,
  timeout = 400,
  stopAtFirstOpen = true,
  arp = null,
  run = null,
  onProgress = null,
  signal = null,
  limit = 4096,
} = {}) {
  const started = Date.now();
  const resolved = resolveTargets({ target, interfaces, limit });
  if (resolved.error) {
    return { ok: false, error: resolved.error, hosts: [], options: { target, ports: ports.map((p) => p.port) } };
  }

  const hostList = resolved.hosts;
  if (hostList.length === 0) {
    return { ok: false, error: `no probeable addresses in ${resolved.cidr}`, hosts: [], options: {} };
  }

  // `probed` counts the addresses whose probes actually finished. It is the
  // only honest source for probedAddresses: hostList.length is what the scan
  // *intended* to cover, and the two differ by exactly the addresses an
  // interrupt skipped.
  let probed = 0;
  const results = await mapPool(hostList, concurrency, async (host) => {
    if (signal?.aborted) return { host, open: [], alive: false, aborted: true };

    const open = [];
    for (const entry of ports) {
      const result = await probePort(host, entry.port, { timeout });
      if (result.status === 'open') {
        open.push({ port: entry.port, service: entry.service ?? serviceName(entry.port), ms: result.ms });
        if (stopAtFirstOpen) break;
      }
    }
    probed += 1;
    if (onProgress) onProgress({ probed, total: hostList.length, host });
    return { host, open, alive: open.length > 0 };
  });

  const aborted = Boolean(signal?.aborted);
  const unprobed = hostList.length - probed;

  // Resolve link-layer addresses before reading the table: a host that only
  // answered a TCP connect may have no ARP entry yet, which would report every
  // device as an unknown vendor. Skipped when a caller supplied a table (tests
  // and API users), because sending packets would be a surprise side effect —
  // and skipped after an interrupt, where finishing the scan quickly matters
  // more than the vendor names of a report that is about to say it is partial.
  if (arp === null && !aborted) {
    await primeArpTable([...hostList, resolved.address].filter(Boolean));
  }

  const table = arp ?? (await arpTable({ run }));
  const own = ownAddresses({ interfaces });
  const hosts = results
    .filter((entry) => entry && entry.alive)
    .map((entry) => {
      const self = own.get(entry.host);
      const device = describeDevice(self?.mac ?? table.get(entry.host));
      return {
        address: entry.host,
        openPorts: entry.open.slice().sort((a, b) => a.port - b.port),
        mac: device.mac,
        vendor: self ? 'this machine' : device.vendor,
        deviceKind: self ? 'self' : device.kind,
        deviceNote: self ? `local interface ${self.name}` : device.note,
      };
    });

  const arpOnly = [...table.entries()]
    .filter(([ip]) => !hosts.some((h) => h.address === ip))
    .filter(([ip]) => !own.has(ip))
    .filter(([, mac]) => !isGroupAddress(mac))
    .map(([ip, mac]) => {
      const device = describeDevice(mac);
      return {
        address: ip,
        openPorts: null,
        mac: device.mac,
        vendor: device.vendor,
        deviceKind: device.kind,
        deviceNote: 'in the ARP table but no probed port answered',
      };
    });

  return {
    ok: true,
    aborted,
    tool: { name: 'netpeek', version: VERSION },
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    network: {
      cidr: resolved.cidr,
      interface: resolved.interface,
      address: resolved.address,
      prefix: resolved.prefix,
      totalAddresses: resolved.total,
      // What the scan set out to probe (the range, cut off at `limit`)…
      plannedAddresses: hostList.length,
      // …and what it actually finished, which differ after an interrupt
      probedAddresses: probed,
      truncated: resolved.truncated,
      limit,
    },
    options: {
      ports: ports.map((p) => p.port),
      concurrency,
      timeout,
      stopAtFirstOpen,
    },
    summary: {
      alive: hosts.length,
      withOpenPorts: hosts.length,
      arpOnly: arpOnly.length,
      openPortTotal: hosts.reduce((acc, h) => acc + h.openPorts.length, 0),
    },
    hosts,
    arpOnly,
    errors: aborted
      ? [
          `scan interrupted after ${probed} of ${hostList.length} addresses ` +
            `(${unprobed} not probed); results are incomplete`,
        ]
      : [],
  };
}

/** List the machine's interfaces in a report-friendly shape. */
export function listInterfaces({ interfaces = null } = {}) {
  const table = interfaces ?? os.networkInterfaces();
  const rows = [];
  for (const [name, addresses] of Object.entries(table)) {
    for (const address of addresses ?? []) {
      const family = address.family === 'IPv4' || address.family === 4 ? 'IPv4' : 'IPv6';
      rows.push({
        name,
        family,
        address: address.address,
        internal: Boolean(address.internal),
        mac: normalizeMac(address.mac),
        netmask: address.netmask ?? null,
        cidr: address.cidr ?? null,
        scopeid: address.scopeid ?? null,
      });
    }
  }
  const preferred = pickInterface(table);
  return {
    ok: true,
    tool: { name: 'netpeek', version: VERSION },
    preferred: preferred ? { name: preferred.name, address: preferred.address } : null,
    interfaces: rows,
  };
}

/** Probe one host on specific ports and report every port's state. */
export async function checkHost({
  host,
  ports = defaultPorts(),
  timeout = 800,
  concurrency = 32,
  arp = null,
  run = null,
} = {}) {
  if (!isIPv4(host)) {
    return { ok: false, error: `not an IPv4 address: ${host}` };
  }
  const started = Date.now();
  const results = await mapPool(ports, concurrency, async (entry) => {
    const result = await probePort(host, entry.port, { timeout });
    return {
      port: entry.port,
      service: entry.service ?? serviceName(entry.port),
      status: result.status,
      ms: result.ms,
      error: result.error,
    };
  });

  const table = arp ?? (await arpTable({ run }));
  const device = describeDevice(table.get(host));

  return {
    ok: true,
    tool: { name: 'netpeek', version: VERSION },
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    host,
    mac: device.mac,
    vendor: device.vendor,
    deviceKind: device.kind,
    deviceNote: device.note,
    openPorts: results.filter((r) => r.status === 'open'),
    closedPorts: results.filter((r) => r.status === 'closed'),
    filteredPorts: results.filter((r) => r.status === 'timeout' || r.status === 'unreachable'),
    ports: results,
  };
}
