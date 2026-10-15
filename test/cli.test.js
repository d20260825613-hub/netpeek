import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { OPTION_NAMES, USAGE } from '../src/args.js';
import { run } from '../src/cli.js';
import { SAMPLE_ARP, SAMPLE_INTERFACES } from './helpers/fixtures.js';

/**
 * Drive the CLI in-process.
 *
 * Spawning a child process per case would test Node's spawn path as much as the
 * CLI, and would not work in a sandbox that denies child-process pipes. Since
 * `run()` takes an injectable io and returns a code instead of calling
 * process.exit, the real code path is still what runs here.
 */
async function runCli(argv, io = {}) {
  let stdout = '';
  let stderr = '';
  const code = await run(argv, {
    stdout: { write: (chunk) => (stdout += chunk), isTTY: false },
    stderr: { write: (chunk) => (stderr += chunk), isTTY: false },
    env: { NO_COLOR: '1' },
    interfaces: SAMPLE_INTERFACES,
    arp: SAMPLE_ARP,
    ...io,
  });
  return { code, stdout, stderr };
}

test('help exits 0 and documents the commands', async () => {
  const { code, stdout } = await runCli(['help']);
  assert.equal(code, 0);
  assert.match(stdout, /netpeek — what is actually on your LAN/);
  assert.match(stdout, /netpeek scan/);
  assert.match(stdout, /netpeek check/);
  assert.match(stdout, /netpeek iface/);
});

test('the help text documents every option the parser accepts', () => {
  for (const name of OPTION_NAMES) {
    assert.ok(USAGE.includes(`--${name}`), `--${name} is accepted but not documented in USAGE`);
  }
});

test('--help prints usage and exits 0, while a bare invocation is a usage error', async () => {
  const help = await runCli(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /Usage/);

  const bare = await runCli([]);
  assert.equal(bare.code, 2, 'no command is a usage problem');
  assert.match(bare.stderr, /no command given/);
  assert.equal(bare.stdout, '');
});

test('--version prints a semver and nothing else on stdout', async () => {
  const { code, stdout } = await runCli(['--version']);
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('the reported version matches package.json', async () => {
  // `netpeek --version` and the version inside every report come from this
  // constant, so it drifting from the manifest is a release bug in itself.
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const { stdout } = await runCli(['--version']);
  assert.equal(stdout.trim(), manifest.version);
});

test('an unknown command is a usage error with the list of real ones', async () => {
  const { code, stderr } = await runCli(['frobnicate']);
  assert.equal(code, 2);
  assert.match(stderr, /unknown command: frobnicate/);
  assert.match(stderr, /scan, check, iface, help/);
});

test('a bad port list is caught before any socket is opened', async () => {
  const { code, stderr } = await runCli(['scan', '127.0.0.1/32', '--ports', 'nope']);
  assert.equal(code, 2);
  assert.match(stderr, /not a port: nope/);
  assert.match(stderr, /--ports 22,80,443/);
});

test('iface lists the injected interfaces as a table', async () => {
  const { code, stdout } = await runCli(['iface']);
  assert.equal(code, 0);
  assert.match(stdout, /WLAN/);
  assert.match(stdout, /192\.168\.2\.108/);
  assert.match(stdout, /would scan: 192\.168\.2\.108 on WLAN/);
});

test('iface --json emits parseable JSON with the preferred interface', async () => {
  const { code, stdout } = await runCli(['iface', '--json']);
  assert.equal(code, 0);
  const report = JSON.parse(stdout);
  assert.equal(report.tool.name, 'netpeek');
  assert.equal(report.preferred.address, '192.168.2.108');
  assert.ok(report.interfaces.length >= 4);
});

test('scan --json on a single port with no listener stays valid JSON', async () => {
  const { code, stdout } = await runCli(['scan', '127.0.0.1/32', '--ports', '9', '--timeout', '150', '--json']);
  assert.equal(code, 0, 'a scan that finds nothing still succeeded');
  const report = JSON.parse(stdout);
  assert.equal(report.ok, true);
  assert.equal(report.network.cidr, '127.0.0.1/32');
  assert.ok(Array.isArray(report.hosts));
});

test('a scan of an unusable target is exit 2, not exit 1', async () => {
  const { code, stderr } = await runCli(['scan', 'not-a-cidr']);
  assert.equal(code, 2);
  assert.match(stderr, /not an IPv4 address/);
});

test('check rejects a hostname, because resolution is deliberately not done', async () => {
  const { code, stderr } = await runCli(['check', 'localhost']);
  assert.equal(code, 2);
  assert.match(stderr, /not an IPv4 address: localhost/);
});

test('check --json reports each port state', async () => {
  const { code, stdout } = await runCli(['check', '127.0.0.1', '--ports', '9', '--timeout', '150', '--json']);
  assert.equal(code, 0);
  const report = JSON.parse(stdout);
  assert.equal(report.ok, true);
  assert.equal(report.host, '127.0.0.1');
  assert.equal(report.ports.length, 1);
  assert.ok(['open', 'closed', 'timeout', 'unreachable'].includes(report.ports[0].status));
});

test('--progress writes to stderr, never to stdout, so JSON stays clean', async () => {
  const { code, stdout, stderr } = await runCli([
    'scan',
    '10.0.0.0/29',
    '--ports',
    '9',
    '--timeout',
    '120',
    '--progress',
    '--json',
  ]);
  assert.equal(code, 0);
  assert.doesNotThrow(() => JSON.parse(stdout), 'progress must not corrupt the JSON report');
  assert.match(stderr, /probing/);
});

test('an aborted scan reports itself as incomplete and exits non-zero', async () => {
  // Regression: an interrupted scan exited 0 and printed a report identical to
  // a finished one, so a script (or a reader) had no way to tell that most of
  // the range had never been looked at.
  const controller = new AbortController();
  controller.abort();
  const { code, stdout, stderr } = await runCli(
    ['scan', '10.0.0.0/29', '--ports', '9', '--timeout', '120', '--json'],
    { abortSignal: controller.signal },
  );
  assert.equal(code, 130, 'an interrupted scan must not exit 0');
  const report = JSON.parse(stdout);
  assert.equal(report.aborted, true);
  assert.equal(report.summary.alive, 0);
  assert.equal(report.network.probedAddresses, 0);
  assert.ok(report.network.probedAddresses < report.network.totalAddresses);
  assert.match(stderr, /interrupted after 0 of 6 addresses/);
});

test('an interrupted scan says so in text output too, not just in JSON', async () => {
  const controller = new AbortController();
  controller.abort();
  const { code, stdout } = await runCli(['scan', '10.0.0.0/29', '--ports', '9', '--timeout', '120'], {
    abortSignal: controller.signal,
  });
  assert.equal(code, 130);
  assert.match(stdout, /0\/6 addresses/);
  assert.match(stdout, /interrupted/);
  assert.match(stdout, /incomplete/);
});

test('an interrupted capped scan counts against the cap, not the whole range', async () => {
  // `10.0.0.0/16` is 65534 addresses, of which --limit plans at most 4096. An
  // interrupt before any probe must not be reported as "0 of 65534": that would
  // describe a scan that was never going to run.
  const controller = new AbortController();
  controller.abort();
  const { code, stderr } = await runCli(
    ['scan', '10.0.0.0/16', '--ports', '9', '--timeout', '120', '--limit', '4096', '--json'],
    { abortSignal: controller.signal },
  );
  assert.equal(code, 130);
  assert.match(stderr, /interrupted after 0 of 4096 addresses/);
  assert.doesNotMatch(stderr, /65534/);
});

test('--ports= with nothing after it is a usage error, not a silent default scan', async () => {
  // Regression: the empty string parsed as falsy, so the whole port validation
  // block was skipped and the scan quietly probed the 11 default ports the user
  // had just asked not to use.
  const { code, stdout, stderr } = await runCli(['scan', '127.0.0.1/32', '--ports=', '--timeout', '150', '--json']);
  assert.equal(code, 2);
  assert.match(stderr, /empty port list/);
  assert.equal(stdout, '', 'nothing should be scanned');
});

test('--ports with only separators is rejected as well', async () => {
  const { code, stderr } = await runCli(['scan', '127.0.0.1/32', '--ports', ',,,']);
  assert.equal(code, 2);
  assert.match(stderr, /no ports given/);
});

test('--limit halts a range before it plans to probe it all', async () => {
  const { code, stdout } = await runCli([
    'scan',
    '10.0.0.0/24',
    '--ports',
    '9',
    '--timeout',
    '120',
    '--limit',
    '4',
    '--json',
  ]);
  assert.equal(code, 0);
  const report = JSON.parse(stdout);
  assert.equal(report.network.probedAddresses, 4);
  assert.equal(report.network.totalAddresses, 254);
  assert.equal(report.network.truncated, true);
});

test('--limit outside the sane range is a usage error', async () => {
  const tooSmall = await runCli(['scan', '10.0.0.0/24', '--limit', '0']);
  assert.equal(tooSmall.code, 2);
  assert.match(tooSmall.stderr, /--limit must be >= 1/);

  const tooBig = await runCli(['scan', '10.0.0.0/24', '--limit', '1000001']);
  assert.equal(tooBig.code, 2);
  assert.match(tooBig.stderr, /--limit must be <= 1000000/);

  const notNumber = await runCli(['scan', '10.0.0.0/24', '--limit', 'lots']);
  assert.equal(notNumber.code, 2);
  assert.match(notNumber.stderr, /--limit expects a number/);
});

test('the --limit help text says what the cap does', async () => {
  const { stdout } = await runCli(['help']);
  assert.match(stdout, /--limit <n>/);
  assert.match(stdout, /default: 4096/);
});

test('text output never contains ANSI escapes when colour is off', async () => {
  const { stdout } = await runCli(['iface']);
  assert.equal(/\u001b\[/.test(stdout), false, 'escape codes leaked into a non-TTY stream');
});
