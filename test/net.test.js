import assert from 'node:assert/strict';
import test from 'node:test';

import {
  hostsInRange,
  intToIp,
  ipToInt,
  isIPv4,
  netmaskToPrefix,
  networkBounds,
  parseTarget,
  pickInterface,
  prefixForAddress,
  prefixToInt,
} from '../src/net.js';

test('ipToInt accepts dotted quads and rejects everything else', () => {
  assert.equal(ipToInt('0.0.0.0'), 0);
  assert.equal(ipToInt('192.168.1.1'), 3232235777);
  assert.equal(ipToInt('255.255.255.255'), 4294967295);

  for (const bad of ['192.168.1', '192.168.1.256', '192.168.1.-1', 'a.b.c.d', '', '192.168.1.1.1', ' 1.2.3.4']) {
    assert.equal(ipToInt(bad), null, `${JSON.stringify(bad)} should not parse`);
  }
});

test('ipToInt is strict about the exact form of an address', () => {
  // Trimming here would hide a quoting bug in whatever produced the string, so
  // parseTarget trims its own input and this stays strict.
  assert.equal(ipToInt(' 1.2.3.4'), null);
  assert.equal(ipToInt('1.2.3.4 '), null);
  assert.equal(ipToInt('01.2.3.4'), ipToInt('1.2.3.4'), 'leading zeros are still digits');
});

test('intToIp round-trips through ipToInt', () => {
  for (const ip of ['0.0.0.0', '10.0.0.1', '172.16.31.255', '192.168.255.254', '255.255.255.255']) {
    assert.equal(intToIp(ipToInt(ip)), ip);
  }
});

test('intToIp handles values above 2^31 without going negative', () => {
  // >>> 0 is easy to forget: a signed shift would produce -1.0.0.0 here
  assert.equal(intToIp(4294967295), '255.255.255.255');
  assert.equal(intToIp(ipToInt('255.0.0.0')), '255.0.0.0');
});

test('isIPv4 is true only for real addresses', () => {
  assert.equal(isIPv4('8.8.8.8'), true);
  assert.equal(isIPv4('8.8.8'), false);
  assert.equal(isIPv4('fe80::1'), false);
  assert.equal(isIPv4(undefined), false);
});

test('prefixToInt builds a contiguous mask', () => {
  assert.equal(prefixToInt(24), ipToInt('255.255.255.0'));
  assert.equal(prefixToInt(32), ipToInt('255.255.255.255'));
  assert.equal(prefixToInt(0), 0);
  for (const bad of [-1, 33, 1.5, '24', null]) {
    assert.equal(prefixToInt(bad), null, `${String(bad)} should be rejected`);
  }
});

test('parseTarget reads address-only, CIDR and bare-prefix forms', () => {
  assert.deepEqual(parseTarget('192.168.1.10'), { address: '192.168.1.10', prefix: null, error: null });
  assert.deepEqual(parseTarget('192.168.1.10/24'), { address: '192.168.1.10', prefix: 24, error: null });
  assert.deepEqual(parseTarget('/24'), { address: null, prefix: 24, error: null });
});

test('parseTarget reports what was wrong instead of guessing', () => {
  assert.match(parseTarget('192.168.1.300').error, /not an IPv4 address/);
  assert.match(parseTarget('192.168.1.1/33').error, /prefix out of range/);
  assert.match(parseTarget('192.168.1.1/abc').error, /not a prefix length/);
  assert.match(parseTarget('').error, /empty target/);
  assert.match(parseTarget(null).error, /empty target/);
});

test('networkBounds masks off the host bits', () => {
  const bounds = networkBounds('192.168.1.37', 24);
  assert.equal(bounds.networkIp, '192.168.1.0');
  assert.equal(bounds.broadcastIp, '192.168.1.255');
});

test('hostsInRange excludes network and broadcast on a normal subnet', () => {
  const { hosts, total, truncated } = hostsInRange('192.168.1.10', 30);
  assert.equal(truncated, false);
  assert.deepEqual(hosts, ['192.168.1.9', '192.168.1.10']);
  // total counts usable addresses, not the size of the subnet (which is 4)
  assert.equal(total, 2);
});

test('hostsInRange keeps both addresses on /31 and the single host on /32', () => {
  // RFC 3021: a /31 point-to-point link uses both addresses, so nothing is
  // reserved and total counts them all.
  const p31 = hostsInRange('10.0.0.0', 31);
  assert.deepEqual(p31.hosts, ['10.0.0.0', '10.0.0.1']);
  assert.equal(p31.total, 2);

  const p32 = hostsInRange('10.0.0.7', 32);
  assert.deepEqual(p32.hosts, ['10.0.0.7']);
  assert.equal(p32.total, 1);
});

test('hostsInRange caps a large range instead of building 16 million strings', () => {
  const { hosts, total, truncated } = hostsInRange('10.0.0.0', 8, { limit: 64 });
  assert.equal(truncated, true);
  assert.equal(hosts.length, 64);
  // 10.0.0.0/8 has 16,777,216 addresses; minus network and broadcast, 16,777,214
  // are usable, and that is what `total` reports so progress output is honest
  // about the size of the job that was capped.
  assert.equal(total, 16777214);
  assert.equal(hosts[0], '10.0.0.1');
});

test('hostsInRange covers a /24 exactly', () => {
  const { hosts, total, truncated } = hostsInRange('192.168.2.108', 24);
  assert.equal(truncated, false);
  assert.equal(total, 254);
  assert.equal(hosts.length, 254);
  assert.equal(hosts[0], '192.168.2.1');
  assert.equal(hosts[253], '192.168.2.254');
});

test('hostsInRange rejects bad input rather than returning junk', () => {
  assert.match(hostsInRange('not-an-ip', 24).error, /not an IPv4 address/);
  assert.match(hostsInRange('10.0.0.1', 99).error, /bad prefix/);
});

test('netmaskToPrefix converts contiguous masks and rejects the rest', () => {
  assert.equal(netmaskToPrefix('255.255.255.0'), 24);
  assert.equal(netmaskToPrefix('255.255.255.252'), 30);
  assert.equal(netmaskToPrefix('0.0.0.0'), 0);
  // A non-contiguous mask is not a real netmask
  assert.equal(netmaskToPrefix('255.0.255.0'), null);
  assert.equal(netmaskToPrefix('nonsense'), null);
});

test('prefixForAddress prefers cidr and falls back to netmask', () => {
  assert.equal(prefixForAddress({ cidr: '192.168.1.5/24', netmask: '255.255.0.0' }), 24);
  assert.equal(prefixForAddress({ netmask: '255.255.255.128' }), 25);
  assert.equal(prefixForAddress({}), null);
});

test('pickInterface prefers a private LAN address over a public one', () => {
  const interfaces = {
    'Ethernet 2': [
      { family: 'IPv4', address: '192.168.56.1', internal: false, netmask: '255.255.255.0', cidr: '192.168.56.1/24' },
    ],
    WLAN: [{ family: 'IPv4', address: '203.0.113.9', internal: false, netmask: '255.255.255.0' }],
    Loopback: [{ family: 'IPv4', address: '127.0.0.1', internal: true }],
  };
  assert.equal(pickInterface(interfaces).address, '192.168.56.1');
});

test('pickInterface ignores loopback and IPv6, and returns null with no candidates', () => {
  const onlyLoopback = { Loopback: [{ family: 'IPv4', address: '127.0.0.1', internal: true }] };
  assert.equal(pickInterface(onlyLoopback), null);
  assert.equal(pickInterface({}), null);
  assert.equal(pickInterface(null), null);

  const v6 = { WLAN: [{ family: 'IPv6', address: 'fe80::1', internal: false }] };
  assert.equal(pickInterface(v6), null);
});

test('pickInterface accepts the numeric family that some Node builds report', () => {
  const interfaces = { eth0: [{ family: 4, address: '10.1.2.3', internal: false }] };
  assert.equal(pickInterface(interfaces).address, '10.1.2.3');
});
