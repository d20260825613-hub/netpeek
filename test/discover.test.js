import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';

import { checkHost, defaultPorts, describeDevice, discover, parsePorts, resolveTargets } from '../src/discover.js';
import { SAMPLE_INTERFACES } from './helpers/fixtures.js';

test('parsePorts reads single ports, lists and ranges', () => {
  assert.deepEqual(parsePorts('22').ports, [{ port: 22, service: 'ssh' }]);
  assert.deepEqual(
    parsePorts('80,22,443').ports.map((p) => p.port),
    [22, 80, 443], // sorted, so output is stable regardless of input order
  );
  const range = parsePorts('1-5');
  assert.deepEqual(range.ports.map((p) => p.port), [1, 2, 3, 4, 5]);
  assert.equal(range.ports[0].service, null);
});

test('parsePorts rejects what it cannot probe, with a reason', () => {
  assert.match(parsePorts('').error, /empty port list/);
  assert.match(parsePorts('0').error, /out of range/);
  assert.match(parsePorts('70000').error, /out of range/);
  assert.match(parsePorts('abc').error, /not a port/);
  assert.match(parsePorts('10-5').error, /bad port range/);
  // A typo like --ports 1-65535 would otherwise try to open 65k sockets
  assert.match(parsePorts('1-65535').error, /too wide/);
});

test('parsePorts labels the ports it knows', () => {
  const parsed = parsePorts('445,3389');
  assert.deepEqual(
    parsed.ports.map((p) => p.service),
    ['smb', 'rdp'],
  );
});

test('defaultPorts returns a fresh array each call', () => {
  const a = defaultPorts();
  a.push({ port: 1, service: 'x' });
  assert.notEqual(defaultPorts().length, a.length);
});

test('resolveTargets uses the private LAN interface when no target is given', () => {
  const resolved = resolveTargets({ interfaces: SAMPLE_INTERFACES });
  assert.equal(resolved.error, null);
  assert.equal(resolved.cidr, '192.168.2.108/24');
  assert.equal(resolved.hosts.length, 254);
  assert.equal(resolved.interface, 'WLAN');
});

test('resolveTargets honours an explicit range and masks host bits', () => {
  const resolved = resolveTargets({ target: '10.0.0.37/30', interfaces: SAMPLE_INTERFACES });
  assert.equal(resolved.cidr, '10.0.0.37/30');
  assert.deepEqual(resolved.hosts, ['10.0.0.37', '10.0.0.38']);
  // /30 has four addresses, of which the network and broadcast are not usable
  assert.equal(resolved.total, 2);
});

test('resolveTargets expands a bare prefix against the default interface', () => {
  const resolved = resolveTargets({ target: '/28', interfaces: SAMPLE_INTERFACES });
  assert.equal(resolved.cidr, '192.168.2.108/28');
  assert.equal(resolved.hosts.length, 14);
});

test('resolveTargets reports a bad target instead of scanning nothing quietly', () => {
  assert.match(resolveTargets({ target: '10.0.0.999', interfaces: SAMPLE_INTERFACES }).error, /not an IPv4/);
  assert.match(resolveTargets({ target: '10.0.0.1/40', interfaces: SAMPLE_INTERFACES }).error, /out of range/);
  assert.match(resolveTargets({ interfaces: {} }).error, /no external IPv4 interface/);
});

test('describeDevice names a vendor when the OUI is known', () => {
  const device = describeDevice('08:00:27:AA:BB:CC');
  assert.equal(device.vendor, 'VirtualBox');
  assert.equal(device.mac, '08:00:27:AA:BB:CC');
  assert.equal(device.kind, 'device');
});

test('describeDevice refuses to invent a vendor for a randomised MAC', () => {
  const device = describeDevice('02:11:22:33:44:55');
  assert.equal(device.vendor, null);
  assert.equal(device.kind, 'randomised');
  assert.match(device.note, /locally administered/);
});

test('describeDevice flags group addresses and missing entries', () => {
  assert.equal(describeDevice('ff:ff:ff:ff:ff:ff').kind, 'group');
  assert.equal(describeDevice('ff:ff:ff:ff:ff:ff').vendor, null);
  assert.equal(describeDevice(null).kind, 'unknown');
  assert.equal(describeDevice(undefined).mac, null);
});

test('describeDevice reports an unknown OUI as unknown, with the MAC kept', () => {
  const device = describeDevice('00:99:88:77:66:55');
  assert.equal(device.vendor, null);
  assert.equal(device.kind, 'unknown-vendor');
  assert.equal(device.mac, '00:99:88:77:66:55');
});

test('discover finds a real listener on a loopback range', async () => {
  // A real socket, not a mock: this is the only test that proves probePort
  // actually reports an open port.
  const server = net.createServer((socket) => socket.end());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const report = await discover({
      target: '127.0.0.1/32',
      ports: [{ port }],
      timeout: 1000,
      arp: new Map(),
    });
    assert.equal(report.ok, true);
    assert.equal(report.summary.alive, 1);
    assert.deepEqual(report.hosts[0].openPorts.map((p) => p.port), [port]);
    assert.equal(report.hosts[0].address, '127.0.0.1');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('discover does not report a closed port as a live host', async () => {
  // Bind and immediately release a port, so nothing is listening but the
  // address is reachable: the answer must be "refused", not "alive".
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));

  const report = await discover({
    target: '127.0.0.1/32',
    ports: [{ port }],
    timeout: 1000,
    arp: new Map(),
  });
  assert.equal(report.ok, true);
  assert.equal(report.summary.alive, 0);
  assert.deepEqual(report.hosts, []);
});

test('discover keeps probing after the first open port only with all-ports', async () => {
  const first = net.createServer((s) => s.end());
  const second = net.createServer((s) => s.end());
  await new Promise((resolve) => first.listen(0, '127.0.0.1', resolve));
  await new Promise((resolve) => second.listen(0, '127.0.0.1', resolve));
  const p1 = first.address().port;
  const p2 = second.address().port;

  try {
    const quick = await discover({
      target: '127.0.0.1/32',
      ports: [{ port: p1 }, { port: p2 }],
      stopAtFirstOpen: true,
      timeout: 1000,
      arp: new Map(),
    });
    assert.equal(quick.hosts[0].openPorts.length, 1);

    const full = await discover({
      target: '127.0.0.1/32',
      ports: [{ port: p1 }, { port: p2 }],
      stopAtFirstOpen: false,
      timeout: 1000,
      arp: new Map(),
    });
    assert.equal(full.hosts[0].openPorts.length, 2);
    const reported = full.hosts[0].openPorts.map((p) => p.port).sort((a, b) => a - b);
    assert.deepEqual(reported, [p1, p2].sort((a, b) => a - b));
  } finally {
    await new Promise((resolve) => first.close(resolve));
    await new Promise((resolve) => second.close(resolve));
  }
});

test('discover reports ARP-only devices separately from live hosts', async () => {
  const arp = new Map([['192.168.2.1', '08:00:27:8E:0A:DA']]);
  const report = await discover({
    target: '127.0.0.1/32',
    ports: [{ port: 1 }],
    timeout: 200,
    arp,
  });
  assert.equal(report.hosts.length, 0);
  assert.equal(report.arpOnly.length, 1);
  assert.equal(report.arpOnly[0].address, '192.168.2.1');
  assert.equal(report.arpOnly[0].vendor, 'VirtualBox');
  assert.equal(report.arpOnly[0].openPorts, null);
});

test('discover filters multicast entries out of the ARP-only list', async () => {
  const arp = new Map([
    ['224.0.0.22', '01:00:5e:00:00:16'],
    ['192.168.2.1', '20:79:18:8E:0A:DA'],
  ]);
  const report = await discover({ target: '127.0.0.1/32', ports: [{ port: 1 }], timeout: 200, arp });
  assert.deepEqual(report.arpOnly.map((h) => h.address), ['192.168.2.1']);
});

test('discover returns a failure object rather than throwing on a bad range', async () => {
  const report = await discover({ target: 'nonsense', ports: [{ port: 80 }], interfaces: SAMPLE_INTERFACES });
  assert.equal(report.ok, false);
  assert.match(report.error, /not an IPv4/);
  assert.deepEqual(report.hosts, []);
});

test('discover reports progress for every address it probed', async () => {
  const seen = [];
  await discover({
    target: '10.0.0.0/29',
    ports: [{ port: 1 }],
    timeout: 150,
    arp: new Map(),
    onProgress: (p) => seen.push(p.probed),
  });
  assert.equal(seen.length, 6); // /29 has 6 usable addresses
  assert.equal(seen[seen.length - 1], 6);
});

test('discover marks an interrupted scan and counts the addresses it really probed', async () => {
  // Regression: aborting a scan skipped the remaining addresses but the report
  // still said probedAddresses = the planned range, carried no aborted flag, and
  // was byte-for-byte a complete report apart from the timing. A user who hit
  // Ctrl-C was told the whole subnet had been scanned.
  const controller = new AbortController();
  const progress = [];
  const report = await discover({
    target: '10.88.0.0/24',
    ports: [{ port: 9 }],
    concurrency: 8,
    timeout: 150,
    arp: new Map(),
    signal: controller.signal,
    onProgress: (p) => {
      progress.push(p.probed);
      if (p.probed === 8) controller.abort();
    },
  });

  const scanned = progress[progress.length - 1];
  assert.equal(report.ok, true, 'a partial report is still a report');
  assert.equal(report.aborted, true);
  assert.equal(report.network.totalAddresses, 254);
  assert.equal(
    report.network.probedAddresses,
    scanned,
    'probedAddresses must be the number of addresses that were actually probed',
  );
  assert.ok(
    report.network.probedAddresses <= scanned,
    `probedAddresses ${report.network.probedAddresses} exceeds the ${scanned} addresses that finished`,
  );
  assert.notEqual(report.network.probedAddresses, report.network.totalAddresses);
  assert.ok(report.errors.some((line) => /interrupted/.test(line)), 'the report must say it is incomplete');
  assert.match(JSON.stringify(report), /interrupted/);
});

test('discover does not flag a scan that ran to completion', async () => {
  const report = await discover({ target: '10.0.0.0/29', ports: [{ port: 1 }], timeout: 150, arp: new Map() });
  assert.equal(report.aborted, false);
  assert.equal(report.network.probedAddresses, 6);
  assert.deepEqual(report.errors, []);
});

test('discover honours the address limit and still reports the whole range', async () => {
  const report = await discover({
    target: '10.0.0.0/24',
    ports: [{ port: 1 }],
    timeout: 150,
    arp: new Map(),
    limit: 4,
  });
  assert.equal(report.network.totalAddresses, 254);
  assert.equal(report.network.probedAddresses, 4);
  assert.equal(report.network.truncated, true);
  assert.equal(report.network.limit, 4);
});

test('discover leaves an injected ARP table alone, without probing the network for it', async () => {
  // The ARP table is a parameter so a library user (or a test) never triggers
  // the UDP nudge or an `arp` subprocess as a surprise side effect.
  let spawned = 0;
  const report = await discover({
    target: '10.0.0.0/29',
    ports: [{ port: 1 }],
    timeout: 150,
    arp: new Map([['10.0.0.1', '20:79:18:8E:0A:DA']]),
    run: () => {
      spawned += 1;
      return '';
    },
  });
  assert.equal(report.ok, true);
  assert.equal(spawned, 0);
  assert.deepEqual(report.arpOnly.map((h) => h.address), ['10.0.0.1']);
});

test('checkHost reports every port state, not just the open ones', async () => {
  const server = net.createServer((s) => s.end());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const openPort = server.address().port;

  const reserved = net.createServer();
  await new Promise((resolve) => reserved.listen(0, '127.0.0.1', resolve));
  const closedPort = reserved.address().port;
  await new Promise((resolve) => reserved.close(resolve));

  try {
    const report = await checkHost({
      host: '127.0.0.1',
      ports: [{ port: openPort }, { port: closedPort }],
      timeout: 1000,
      arp: new Map(),
    });
    assert.equal(report.ok, true);
    assert.deepEqual(report.openPorts.map((p) => p.port), [openPort]);
    assert.deepEqual(report.closedPorts.map((p) => p.port), [closedPort]);
    assert.equal(report.ports.length, 2);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('checkHost rejects anything that is not an IPv4 literal', async () => {
  const report = await checkHost({ host: 'example.com' });
  assert.equal(report.ok, false);
  assert.match(report.error, /not an IPv4 address/);
});
