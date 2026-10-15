/**
 * Rendering: text for a terminal, JSON for a program.
 *
 * One rule the whole file follows: never print a value the tool did not
 * actually observe. An unknown vendor is shown as "unknown", not guessed from
 * the MAC, and a device that only appears in the ARP table is listed separately
 * rather than presented as a live host.
 */

const ANSI = {
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  green: '\u001b[32m',
  yellow: '\u001b[33m',
  cyan: '\u001b[36m',
  red: '\u001b[31m',
};

/** Should this stream get colour? Follows NO_COLOR, then the flag, then TTY. */
export function shouldUseColor({ flag, stream, env = process.env } = {}) {
  if (flag === false) return false;
  if (flag === true) return true;
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') return false;
  return Boolean(stream?.isTTY);
}

function paint(text, colour, enabled) {
  if (!enabled) return text;
  return `${ANSI[colour] ?? ''}${text}${ANSI.reset}`;
}

/** Format a port with its service name when one is known. */
export function formatPort(entry) {
  return entry.service ? `${entry.port}/${entry.service}` : String(entry.port);
}

/** Human wording for a probe outcome. */
export function describeStatus(status) {
  switch (status) {
    case 'open':
      return 'open';
    case 'closed':
      return 'closed (refused)';
    case 'timeout':
      return 'no answer';
    case 'unreachable':
      return 'unreachable';
    default:
      return status;
  }
}

function deviceCell(host) {
  if (!host.mac) return 'unknown (not in ARP table)';
  if (host.vendor) return `${host.vendor} ${host.mac}`;
  if (host.deviceKind === 'randomised') return `randomised MAC ${host.mac}`;
  return `unknown vendor ${host.mac}`;
}

/** Render a scan report as text. */
export function renderScan(report, { color = false } = {}) {
  if (!report.ok) return `${paint('netpeek:', 'red', color)} ${report.error}\n`;

  const lines = [];
  const net = report.network;
  // The denominator is what this run set out to probe: the range, capped by
  // --limit. The full size of the uncapped range is the truncation note's job;
  // printing `totalAddresses` here would claim a /16 scan that hit the cap
  // reached 65534 addresses.
  const planned = net.plannedAddresses ?? net.totalAddresses;
  lines.push(
    `${paint('netpeek', 'bold', color)} scanned ${paint(net.cidr, 'cyan', color)}` +
      `${net.interface ? ` on ${net.interface}` : ''}` +
      ` — ${net.probedAddresses}/${planned} addresses, ` +
      `${report.options.ports.length} port(s), ${report.durationMs} ms`,
  );
  if (net.truncated) {
    // The cap is a property of the range, not of the prefix: a *shorter* prefix
    // is what makes the range bigger, and a longer one can never cover it, so
    // the only useful advice is a different range or a raised limit.
    lines.push(
      paint(
        `  note: the range holds ${net.totalAddresses} addresses, but only the first ${net.limit} would be probed; ` +
          'scan a narrower range, or raise the cap with --limit',
        'yellow',
        color,
      ),
    );
  }
  if (report.aborted) {
    lines.push(
      paint(
        `  note: scan interrupted after ${net.probedAddresses} of ${net.plannedAddresses ?? net.totalAddresses} ` +
          'addresses — results are incomplete',
        'red',
        color,
      ),
    );
  }
  lines.push('');

  if (report.hosts.length === 0) {
    lines.push(
      report.aborted ? '  no live hosts found in the part that was scanned' : '  no live hosts found on the probed ports',
    );
    lines.push(
      paint(
        '  note: a device that answers none of these ports (or is asleep) cannot be seen by TCP probing',
        'dim',
        color,
      ),
    );
  } else {
    lines.push(`  ${paint('ADDRESS'.padEnd(16), 'bold', color)}${paint('OPEN PORTS'.padEnd(30), 'bold', color)}DEVICE`);
    for (const host of report.hosts) {
      const ports = host.openPorts.map((p) => formatPort(p)).join(', ');
      const suffix = report.options.stopAtFirstOpen && host.openPorts.length === 1 ? ' (first open port)' : '';
      lines.push(`  ${host.address.padEnd(16)}${(ports + suffix).padEnd(30)}${deviceCell(host)}`);
    }
  }

  if (report.arpOnly.length > 0) {
    lines.push('');
    lines.push(
      `  ${paint('seen in the ARP table but no probed port answered', 'yellow', color)} ` +
        `(${report.arpOnly.length})`,
    );
    for (const host of report.arpOnly) {
      lines.push(`  ${host.address.padEnd(16)}${''.padEnd(30)}${deviceCell(host)}`);
    }
  }

  lines.push('');
  lines.push(
    `  ${report.summary.alive} live, ${report.summary.openPortTotal} open port(s), ` +
      `${report.summary.arpOnly} ARP-only entr${report.summary.arpOnly === 1 ? 'y' : 'ies'}`,
  );
  return `${lines.join('\n')}\n`;
}

/** Render a single-host check as text. */
export function renderCheck(report, { color = false } = {}) {
  if (!report.ok) return `${paint('netpeek:', 'red', color)} ${report.error}\n`;

  const lines = [];
  lines.push(`${paint('netpeek', 'bold', color)} checked ${paint(report.host, 'cyan', color)} — ${report.durationMs} ms`);
  lines.push(`  device: ${deviceCell(report)}`);
  if (report.deviceNote) lines.push(paint(`  note: ${report.deviceNote}`, 'dim', color));
  lines.push('');
  // The port column has to fit the longest label in this report: "65535" is
  // five characters and "8080/http-alt" is thirteen. A fixed width that the
  // longest label overflows pushes every following column out of line, which is
  // exactly what a table is for.
  const portWidth = Math.max(14, ...report.ports.map((entry) => formatPort(entry).length + 2));
  const stateWidth = Math.max(18, ...report.ports.map((entry) => describeStatus(entry.status).length + 2));
  lines.push(
    `  ${paint('PORT'.padEnd(portWidth), 'bold', color)}${paint('STATE'.padEnd(stateWidth), 'bold', color)}LATENCY`,
  );
  for (const entry of report.ports) {
    const label = formatPort(entry);
    const colour = entry.status === 'open' ? 'green' : entry.status === 'closed' ? 'dim' : 'yellow';
    lines.push(
      `  ${label.padEnd(portWidth)}${paint(describeStatus(entry.status).padEnd(stateWidth), colour, color)}` +
        `${entry.status === 'timeout' ? '-' : `${entry.ms} ms`}`,
    );
  }
  lines.push('');
  lines.push(
    `  ${report.openPorts.length} open, ${report.closedPorts.length} refused, ${report.filteredPorts.length} filtered/no answer`,
  );
  return `${lines.join('\n')}\n`;
}

/** Fit a cell to a fixed width, truncating with an ellipsis when too long. */
function fit(text, width) {
  const value = String(text ?? '');
  if (value.length <= width) return value.padEnd(width);
  return `${value.slice(0, width - 1)}…`;
}

/** Render the interface list as text. */
export function renderInterfaces(report, { color = false } = {}) {
  const lines = [];
  lines.push(`${paint('netpeek', 'bold', color)} ${report.interfaces.length} address(es) on this machine`);
  if (report.preferred) {
    lines.push(`  would scan: ${paint(report.preferred.address, 'cyan', color)} on ${report.preferred.name}`);
  }
  lines.push('');
  // Widths are fixed and cells are truncated, because IPv6 addresses and long
  // Windows adapter names otherwise push every following column out of line.
  lines.push(
    `  ${paint('NAME'.padEnd(26), 'bold', color)}${paint('FAMILY'.padEnd(7), 'bold', color)}` +
      `${paint('ADDRESS'.padEnd(42), 'bold', color)}${paint('MAC'.padEnd(18), 'bold', color)}SCOPE`,
  );
  for (const iface of report.interfaces) {
    const scope = iface.internal ? 'internal' : 'external';
    lines.push(
      `  ${fit(iface.name, 26)}${iface.family.padEnd(7)}${fit(iface.address, 42)}${fit(iface.mac ?? '-', 18)}${scope}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

/** Render any report as JSON, mapping Infinity to null so it stays valid. */
export function renderJson(value, { pretty = false } = {}) {
  return `${JSON.stringify(value, (_key, item) => (item === Infinity ? null : item), pretty ? 2 : 0)}\n`;
}
