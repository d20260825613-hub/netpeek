import assert from 'node:assert/strict';
import test from 'node:test';

import { ALIASED_NAMES, OPTION_NAMES, USAGE, parseArgs } from '../src/args.js';

test('scan takes a target and defaults the numeric options', () => {
  const parsed = parseArgs(['scan', '192.168.1.0/24']);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.command, 'scan');
  assert.deepEqual(parsed.positional, ['192.168.1.0/24']);
  assert.equal(parsed.values.concurrency, 128);
  assert.equal(parsed.values.timeout, 400);
  assert.equal(parsed.values['all-ports'], false);
  assert.equal(parsed.values.json, false);
});

test('scan without a target is valid: it means "my own subnet"', () => {
  const parsed = parseArgs(['scan']);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.positional, []);
});

test('long options accept both --opt value and --opt=value', () => {
  for (const argv of [
    ['scan', '--ports', '22,80'],
    ['scan', '--ports=22,80'],
  ]) {
    const parsed = parseArgs(argv);
    assert.equal(parsed.ok, true, JSON.stringify(argv));
    assert.equal(parsed.values.ports, '22,80');
  }
});

test('short options bundle and glue values the way users type them', () => {
  assert.equal(parseArgs(['scan', '-c256']).values.concurrency, 256);
  assert.equal(parseArgs(['scan', '-c', '64']).values.concurrency, 64);
  assert.equal(parseArgs(['scan', '-t1500']).values.timeout, 1500);
});

test('an unknown command is reported as a command error, not a path', () => {
  const parsed = parseArgs(['scna']);
  assert.equal(parsed.ok, false);
  assert.match(parsed.message, /unknown command: scna/);
  assert.match(parsed.hint, /scan/);
});

test('an unknown option names itself and points at the help', () => {
  const parsed = parseArgs(['scan', '--nonsense']);
  assert.equal(parsed.ok, false);
  assert.match(parsed.message, /unknown option: --nonsense/);
  assert.match(parsed.hint, /netpeek help/);
});

test('a valueless option says so instead of reading the next flag', () => {
  const parsed = parseArgs(['scan', '--ports']);
  assert.equal(parsed.ok, false);
  assert.match(parsed.message, /--ports requires a value/);
  assert.match(parsed.hint, /--ports <value>/);
});

test('numeric options reject non-numbers and out-of-range values', () => {
  const notNumber = parseArgs(['scan', '--concurrency', 'many']);
  assert.equal(notNumber.ok, false);
  assert.match(notNumber.message, /expects a number/);

  const tooSmall = parseArgs(['scan', '--concurrency', '0']);
  assert.equal(tooSmall.ok, false);
  assert.match(tooSmall.message, /must be >= 1/);

  const tooBig = parseArgs(['scan', '--concurrency', '99999']);
  assert.equal(tooBig.ok, false);
  assert.match(tooBig.message, /must be <= 4096/);
});

test('negatable switches understand the --no- form', () => {
  assert.equal(parseArgs(['scan', '--progress']).values.progress, true);
  assert.equal(parseArgs(['scan', '--no-progress']).values.progress, false);
  assert.equal(parseArgs(['scan', '--no-color']).values.color, false);
  assert.equal(parseArgs(['scan', '--color']).values.color, true);
});

test('--no- on an option that takes a value is an error, not a silent switch', () => {
  const parsed = parseArgs(['scan', '--no-ports']);
  assert.equal(parsed.ok, false);
  assert.match(parsed.message, /requires a value|unknown option/);
});

test('check requires exactly one host', () => {
  assert.equal(parseArgs(['check', '192.168.1.1']).ok, true);

  const missing = parseArgs(['check']);
  assert.equal(missing.ok, false);
  assert.match(missing.message, /check needs a host/);

  const tooMany = parseArgs(['check', '10.0.0.1', '10.0.0.2']);
  assert.equal(tooMany.ok, false);
  assert.match(tooMany.message, /takes one host/);
});

test('scan rejects a second target instead of ignoring it', () => {
  const parsed = parseArgs(['scan', '10.0.0.0/24', '10.0.1.0/24']);
  assert.equal(parsed.ok, false);
  assert.match(parsed.message, /scan takes one target/);
});

test('-- ends option parsing so a weird target is still a target', () => {
  const parsed = parseArgs(['scan', '--', '--weird']);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.positional, ['--weird']);
});

test('help and version are recognised without a command', () => {
  assert.equal(parseArgs(['--help']).command, 'help');
  assert.equal(parseArgs(['-h']).command, 'help');
  assert.equal(parseArgs(['--version']).command, 'help');
});

test('a bare invocation explains the commands instead of scanning something', () => {
  const parsed = parseArgs([]);
  assert.equal(parsed.ok, false);
  assert.match(parsed.message, /no command given/);
});

test('every short alias points at a real option', () => {
  // A typo here would surface as "unknown option -c" for a flag the help text
  // advertises, which is a confusing failure to debug from the outside.
  for (const [shortName, longName] of ALIASED_NAMES) {
    assert.ok(OPTION_NAMES.includes(longName), `-${shortName} points at --${longName}, which does not exist`);
  }
});

test('the help text documents every option the parser accepts', () => {
  for (const name of OPTION_NAMES) {
    if (['help', 'version'].includes(name)) continue; // shown in the Options block as -h/-v
    assert.ok(USAGE.includes(`--${name}`), `--${name} is accepted but not documented in USAGE`);
  }
});
