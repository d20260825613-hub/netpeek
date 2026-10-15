import assert from 'node:assert/strict';
import test from 'node:test';

import { renderCheck, renderScan } from '../src/reporter.js';

/**
 * Rendering is a pure string function, so these tests feed it a literal report.
 * That keeps the assertions about columns and wording exact, without a socket or
 * a scan in the way.
 */

/** A finished, untruncated scan report: `network` and `report` override blocks. */
function report(network = {}, top = {}) {
  return {
    ok: true,
    aborted: false,
    durationMs: 12,
    options: { ports: [9], stopAtFirstOpen: true },
    summary: { alive: 0, withOpenPorts: 0, arpOnly: 0, openPortTotal: 0 },
    hosts: [],
    arpOnly: [],
    errors: [],
    ...top,
    network: {
      cidr: '10.0.0.0/24',
      interface: null,
      totalAddresses: 254,
      probedAddresses: 254,
      // What a real scan would have planned, unless a test says otherwise
      plannedAddresses: network.probedAddresses ?? 254,
      truncated: false,
      limit: 4096,
      ...network,
    },
  };
}

/** Column index at which `needle` starts, for a line that is known to hold it. */
function columnOf(line, needle) {
  const index = line.indexOf(needle);
  assert.notEqual(index, -1, `"${needle}" is not in "${line}"`);
  return index;
}

test('renderScan says how many addresses were actually probed, not how many were planned', () => {
  // Regression: an interrupted scan reported `254/254 addresses` (the planned
  // range) and carried no sign of the interrupt at all, so a report covering 30
  // of 254 addresses looked exactly like a completed one.
  const interrupted = renderScan(
    report(
      { probedAddresses: 30, plannedAddresses: 254, totalAddresses: 254 },
      { aborted: true, errors: ['scan interrupted after 30 of 254 addresses'] },
    ),
  );

  assert.match(interrupted, /30\/254 addresses/);
  assert.doesNotMatch(interrupted, /— 254\/254/);
  assert.match(interrupted, /scan interrupted after 30 of 254 addresses/);
  assert.match(interrupted, /incomplete/);
  // "nothing found" and "stopped before looking everywhere" are different answers
  assert.match(interrupted, /no live hosts found in the part that was scanned/);
});

test('renderScan adds no interruption wording to a scan that finished', () => {
  const complete = renderScan(report());
  assert.match(complete, /254\/254 addresses/);
  assert.doesNotMatch(complete, /interrupt|incomplete/i);
  assert.match(complete, /no live hosts found on the probed ports/);
});

test('renderScan tells the user to narrow the range or raise the cap, never a longer prefix', () => {
  // Regression: the note read "use a longer prefix to cover it all". A longer
  // prefix is a *smaller* range, and the two prefixes that trigger the note
  // (/8, /16) cannot be covered by any longer prefix at all.
  const truncated = renderScan(
    report({ cidr: '10.0.0.0/16', totalAddresses: 65534, probedAddresses: 4096, plannedAddresses: 4096, truncated: true }),
  );
  assert.doesNotMatch(truncated, /longer prefix/);
  assert.match(truncated, /--limit/);
  assert.match(truncated, /narrower range/);
  assert.match(truncated, /65534 addresses/);
  // The header counts what was planned, not the whole range it was cut from
  assert.match(truncated, /4096\/4096 addresses/);
  assert.doesNotMatch(truncated, /65534\/65534/);
});

test('renderScan reports an interrupted and capped scan as interrupted within the cap', () => {
  const both = renderScan(
    report(
      { cidr: '10.0.0.0/16', totalAddresses: 65534, plannedAddresses: 4096, probedAddresses: 100, truncated: true },
      { aborted: true },
    ),
  );
  assert.match(both, /100\/4096 addresses/);
  assert.match(both, /interrupted after 100 of 4096 addresses/);
  assert.match(both, /first 4096 would be probed/);
});

test('renderScan uses the planned count when an aborted scan was also capped', () => {
  // The header and the note have to agree with the CLI's own stderr line, and
  // with the report's plannedAddresses: "of 65534" would be a range netpeek
  // never intended to walk in one run.
  const capped = report(
    { cidr: '10.0.0.0/16', totalAddresses: 65534, plannedAddresses: 4096, probedAddresses: 120, truncated: true },
    { aborted: true },
  );
  const text = renderScan(capped);
  assert.doesNotMatch(text, /of 65534 addresses —/);
  assert.match(text, /— 120\/4096 addresses/);
  assert.match(text, /interrupted after 120 of 4096 addresses/);
  assert.match(text, /holds 65534 addresses/);
});

test('renderCheck lines the STATE column up for both short and long port labels', () => {
  // Regression: PORT was padded to a fixed 14 characters, so "8080/http-alt"
  // (13 characters) overflowed the column and pushed its STATE three columns to
  // the right of a row whose label was "65535".
  const ports = [
    { port: 65535, service: null, status: 'closed', ms: 1 },
    { port: 135, service: 'msrpc', status: 'open', ms: 2 },
    { port: 8080, service: 'http-alt', status: 'closed', ms: 3 },
    { port: 22, service: 'ssh', status: 'timeout', ms: 400 },
  ];
  const counts = (status) => ports.filter((p) => p.status === status).length;
  const text = renderCheck({
    ok: true,
    host: '127.0.0.1',
    durationMs: 5,
    mac: null,
    vendor: null,
    deviceKind: 'unknown',
    deviceNote: null,
    ports,
    openPorts: ports.filter((p) => p.status === 'open'),
    closedPorts: ports.filter((p) => p.status === 'closed'),
    filteredPorts: ports.filter((p) => p.status === 'timeout' || p.status === 'unreachable'),
  });

  // Port rows only: the "1 open, 2 refused" summary also starts with a number.
  const rows = text.split('\n').filter((line) => /^\s+\d+(\/[\w-]+)?\s{2,}\S/.test(line));
  assert.equal(rows.length, ports.length);

  // Every row's column layout has to match the header's, or the table is just a
  // pile of numbers. Comparing the label column catches a long label overflowing
  // it, and comparing the state column catches a description doing the same.
  const header = text.split('\n').find((line) => line.includes('LATENCY'));
  const labelWidth = columnOf(header, 'STATE') - columnOf(header, 'PORT');

  const labels = [];
  for (const row of rows) {
    const label = row.slice(2, 2 + labelWidth);
    assert.match(label.trim(), /^\d+(\/[\w-]+)?$/, `the label column does not hold a port label: "${label}"`);
    labels.push(label.trim());
    const state = row.slice(2 + labelWidth);
    const name = ['closed (refused)', 'no answer', 'unreachable', 'open'].find((text) => state.startsWith(text));
    assert.ok(name, `the state column does not start with a state description: "${state}"`);
    // The description starts exactly under the STATE header, and the latency
    // value sits in the column the header calls LATENCY.
    assert.equal(state.indexOf(name), 0);
    assert.match(state.slice(18), /^(\d+ ms|-)$/, `latency column is out of line in "${row}"`);
  }
  assert.deepEqual(labels, ['65535', '135/msrpc', '8080/http-alt', '22/ssh']);

  // …and the descriptions do not run into the latency column.
  assert.equal(counts('closed'), 2);
  assert.match(text, /1 open, 2 refused, 1 filtered\/no answer/);
  assert.match(rows.find((line) => line.includes('8080')), /closed \(refused\)  3 ms$/);
});

test('renderCheck keeps its column widths sane with a single short label', () => {
  const text = renderCheck({
    ok: true,
    host: '127.0.0.1',
    durationMs: 1,
    mac: null,
    vendor: null,
    deviceKind: 'unknown',
    deviceNote: null,
    ports: [{ port: 9, service: null, status: 'closed', ms: 1 }],
    openPorts: [],
    closedPorts: [{ port: 9 }],
    filteredPorts: [],
  });
  assert.match(text, /PORT\s+STATE\s+LATENCY/);
  assert.match(text, /^ {2}9 {13}closed \(refused\) {2}1 ms$/m);
});
