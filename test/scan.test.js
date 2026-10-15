import assert from 'node:assert/strict';
import test from 'node:test';

import {
  COMMON_PORTS,
  arpTable,
  mapPool,
  normalizeShortMac,
  parseBsdArp,
  parseProcNetArp,
  parseWindowsArp,
  readArpTable,
  serviceName,
} from '../src/scan.js';
import { isGroupAddress, isLocallyAdministered, normalizeMac, vendorFor } from '../src/mac.js';

test('serviceName knows common ports and returns null for the rest', () => {
  assert.equal(serviceName(22), 'ssh');
  assert.equal(serviceName(445), 'smb');
  assert.equal(serviceName(12345), null);
});

test('the default port set has no duplicates', () => {
  const ports = COMMON_PORTS.map((p) => p.port);
  assert.equal(new Set(ports).size, ports.length);
  for (const port of ports) assert.ok(port > 0 && port < 65536, `${port} out of range`);
});

test('mapPool preserves input order even when work finishes out of order', async () => {
  const items = [30, 10, 20, 5];
  const results = await mapPool(items, 4, async (ms) => {
    await new Promise((resolve) => setTimeout(resolve, ms));
    return ms * 2;
  });
  assert.deepEqual(results, [60, 20, 40, 10]);
});

test('mapPool never exceeds its concurrency limit', async () => {
  let inFlight = 0;
  let peak = 0;
  const items = Array.from({ length: 24 }, (_, i) => i);
  await mapPool(items, 5, async () => {
    inFlight += 1;
    peak = Math.max(peak, inFlight);
    await new Promise((resolve) => setTimeout(resolve, 1));
    inFlight -= 1;
  });
  assert.ok(peak <= 5, `peak concurrency was ${peak}`);
});

test('mapPool survives a throwing worker instead of rejecting everything', async () => {
  const results = await mapPool([1, 2, 3], 2, async (n) => {
    if (n === 2) throw new Error('boom');
    return n;
  });
  assert.equal(results[0], 1);
  assert.equal(results[2], 3);
  assert.match(results[1].error, /boom/);
});

test('mapPool with an empty list resolves to an empty list', async () => {
  assert.deepEqual(await mapPool([], 4, async () => 1), []);
});

test('parseWindowsArp reads the dashed dynamic/static rows', () => {
  const table = parseWindowsArp(`
Interface: 192.168.2.108 --- 0x5
  Internet Address      Physical Address      Type
  192.168.2.1           20-79-18-8e-0a-da     dynamic
  192.168.2.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
`);
  assert.equal(table.get('192.168.2.1'), '20:79:18:8E:0A:DA');
  assert.equal(table.get('192.168.2.255'), 'FF:FF:FF:FF:FF:FF');
  assert.equal(table.size, 3);
});

test('parseWindowsArp works on a localised Windows, where the type column is not English', () => {
  // Regression: the parser originally required the literal words "static" or
  // "dynamic" in the type column, so a Chinese Windows (which prints 动态/静态)
  // returned an empty table. Every device was then reported as an unknown
  // vendor, with nothing in the output suggesting why.
  const table = parseWindowsArp(
    [
      '',
      '接口: 192.168.2.108 --- 0x7',
      '  Internet 地址         物理地址              类型',
      '  192.168.2.1           80-ae-54-8b-6a-57     动态',
      '  192.168.2.255         ff-ff-ff-ff-ff-ff     静态',
      '',
    ].join('\r\n'),
  );
  assert.equal(table.size, 2);
  assert.equal(table.get('192.168.2.1'), '80:AE:54:8B:6A:57');
  assert.equal(table.get('192.168.2.255'), 'FF:FF:FF:FF:FF:FF');
});

test('parseWindowsArp skips all-zero placeholder rows', () => {
  const table = parseWindowsArp('  192.168.1.50   00-00-00-00-00-00   dynamic\n');
  assert.equal(table.size, 0);
});

test('parseBsdArp reads the macOS parenthesised form', () => {
  const table = parseBsdArp(`
? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.7) at 20:79:18:8e:a:da on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
`);
  assert.equal(table.get('192.168.1.1'), '00:11:22:33:44:55');
  // single-digit groups must be zero-padded, not truncated
  assert.equal(table.get('192.168.1.7'), '20:79:18:8E:0A:DA');
  // an incomplete entry has no MAC and must be skipped
  assert.equal(table.has('192.168.1.9'), false);
});

test('parseProcNetArp reads the Linux table and skips incomplete entries', () => {
  const table = parseProcNetArp(`IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         20:79:18:8e:0a:da     *        wlan0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        wlan0
`);
  assert.equal(table.get('192.168.1.1'), '20:79:18:8E:0A:DA');
  // Flags 0x0 means the kernel has not resolved the MAC yet
  assert.equal(table.has('192.168.1.50'), false);
});

test('parseBsdArp also tolerates the Windows-style rows some builds print', () => {
  const table = parseBsdArp('  10.0.0.5   aa-bb-cc-dd-ee-ff   dynamic\n');
  assert.equal(table.get('10.0.0.5'), 'AA:BB:CC:DD:EE:FF');
});

test('readArpTable returns an empty map instead of throwing when the source is missing', () => {
  const table = readArpTable({
    platform: 'linux',
    readFile: () => {
      throw new Error('ENOENT');
    },
  });
  assert.equal(table.size, 0);
  assert.deepEqual([...readArpTable({ platform: 'sunos' }).entries()], []);
});

test('arpTable reads /proc/net/arp on Linux without starting a subprocess', async () => {
  // Regression: the call site passed readFileSync as the `run` option, so
  // neither guard inside readArpTable matched, the function returned an empty
  // map, and every Linux scan silently spawned `arp -an` it did not need — the
  // /proc branch was unreachable dead code.
  let spawned = 0;
  const procText = [
    'IP address       HW type     Flags       HW address            Mask     Device',
    '192.168.2.1      0x1         0x2         20:79:18:8e:0a:da     *        wlan0',
    '',
  ].join('\n');

  const linux = await arpTable({
    platform: 'linux',
    readFile: () => procText,
    run: () => {
      spawned += 1;
      return '';
    },
  });

  assert.equal(spawned, 0, 'the kernel table was available, so no command should have run');
  assert.equal(linux.get('192.168.2.1'), '20:79:18:8E:0A:DA');
});

test('arpTable falls back to the arp command when /proc/net/arp has nothing usable', async () => {
  const calls = [];
  const table = await arpTable({
    platform: 'linux',
    readFile: () => 'IP address       HW type     Flags       HW address            Mask     Device\n',
    run: (command, args) => {
      calls.push([command, args]);
      return '? (192.168.2.7) at 20:79:18:8e:a:da on wlan0 [ethernet]\n';
    },
  });

  assert.deepEqual(calls, [['arp', ['-an']]]);
  assert.equal(table.get('192.168.2.7'), '20:79:18:8E:0A:DA');
});

test('normalizeShortMac pads, rejects junk, and handles every separator', () => {
  assert.equal(normalizeShortMac('0:11:22:33:44:55'), '00:11:22:33:44:55');
  assert.equal(normalizeShortMac('AA-BB-CC-DD-EE-FF'), 'AA:BB:CC:DD:EE:FF');
  assert.equal(normalizeShortMac('aabb.ccdd.eeff'), 'AA:BB:CC:DD:EE:FF');
  assert.equal(normalizeShortMac('(incomplete)'), null);
  assert.equal(normalizeShortMac('<incomplete>'), null);
  assert.equal(normalizeShortMac(''), null);
  assert.equal(normalizeShortMac('zz:zz:zz:zz:zz:zz'), null);
});

test('normalizeMac accepts the common notations and rejects partial ones', () => {
  assert.equal(normalizeMac('20:79:18:8e:0a:da'), '20:79:18:8E:0A:DA');
  assert.equal(normalizeMac('20-79-18-8E-0A-DA'), '20:79:18:8E:0A:DA');
  assert.equal(normalizeMac('2079188e0ada'), '20:79:18:8E:0A:DA');
  assert.equal(normalizeMac('20:79:18'), null);
  assert.equal(normalizeMac(null), null);
});

test('vendorFor matches the known prefixes', () => {
  // These prefixes are in the table on purpose: the sample machine's own OUI is
  // not, which is exactly the "unknown vendor" path the next test covers.
  assert.equal(vendorFor('08:00:27:aa:bb:cc'), 'VirtualBox');
  assert.equal(vendorFor('0a:00:27:00:00:03'), 'VirtualBox (host-only)');
  assert.equal(vendorFor('b8:27:eb:11:22:33'), 'Raspberry Pi Foundation');
  assert.equal(vendorFor('00:1c:14:00:11:22'), 'VMware');
  // Separator style must not change the answer
  assert.equal(vendorFor('08:00:27:AA:BB:CC'), vendorFor('08-00-27-aa-bb-cc'));
});

test('vendorFor returns null rather than guessing for an unknown prefix', () => {
  assert.equal(vendorFor('02:11:22:33:44:55'), null);
  assert.equal(vendorFor('not-a-mac'), null);
});

test('isLocallyAdministered detects virtual and randomised adapters', () => {
  // 0x02 bit set: 02:, 0A:, 52:, 06:
  assert.equal(isLocallyAdministered('02:11:22:33:44:55'), true);
  assert.equal(isLocallyAdministered('0a:00:27:00:00:03'), true);
  assert.equal(isLocallyAdministered('52:54:00:12:34:56'), true);
  // A real vendor OUI has that bit clear
  assert.equal(isLocallyAdministered('b8:27:eb:11:22:33'), false);
});

test('isGroupAddress detects multicast and broadcast', () => {
  assert.equal(isGroupAddress('ff:ff:ff:ff:ff:ff'), true);
  assert.equal(isGroupAddress('01:00:5e:00:00:16'), true);
  assert.equal(isGroupAddress('20:79:18:8e:0a:da'), false);
  assert.equal(isGroupAddress('nonsense'), false);
});
