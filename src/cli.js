/**
 * CLI orchestration: argv in, exit code out.
 *
 * The only layer that touches process streams, and the only one that decides an
 * exit code. `io` is injectable so tests can drive the real code path instead of
 * spawning a child process.
 */

import process from 'node:process';

import { USAGE, parseArgs } from './args.js';
import { VERSION, checkHost, defaultPorts, discover, listInterfaces, parsePorts } from './discover.js';
import { renderCheck, renderInterfaces, renderJson, renderScan, shouldUseColor } from './reporter.js';

export const EXIT = {
  OK: 0,
  FAILED: 1,
  USAGE: 2,
};

/**
 * Run one command.
 *
 * `io` may supply stdout, stderr and env. Nothing here calls process.exit; the
 * bin entry assigns the returned code, which keeps the function safe to call
 * from a test or from another program.
 */
export async function run(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const env = io.env ?? process.env;
  // Named `abortSignal`, not `signal`: `io` is also a test seam, and a test that
  // injects its own `io.signal` would otherwise collide with this and silently
  // turn every command into "unknown option".
  const abortSignal = io.abortSignal ?? null;

  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    stderr.write(`netpeek: ${parsed.message}\n`);
    if (parsed.hint) stderr.write(`  ${parsed.hint}\n`);
    stderr.write('Run "netpeek help" for usage.\n');
    return EXIT.USAGE;
  }

  const { command, values, positional } = parsed;
  const color = shouldUseColor({ flag: values.color, stream: stdout, env });

  // A bare `help` is a deliberate request, so it exits 0; the usage fallback
  // when no command was given is a usage error, so it exits 2. Mixing the two
  // into one branch is how `--version` ended up printing help and exiting 2.
  if (values.version) {
    stdout.write(`${VERSION}\n`);
    return EXIT.OK;
  }
  if (values.help || command === 'help') {
    stdout.write(USAGE);
    return EXIT.OK;
  }

  let ports = defaultPorts();
  if (values.ports) {
    const parsedPorts = parsePorts(values.ports);
    if (parsedPorts.error) {
      stderr.write(`netpeek: ${parsedPorts.error}\n`);
      stderr.write('  for example --ports 22,80,443 or --ports 1-1024\n');
      return EXIT.USAGE;
    }
    ports = parsedPorts.ports;
  }

  const progress = values.progress
    ? ({ probed, total }) => {
        if (probed % 16 === 0 || probed === total) {
          stderr.write(`\r  probing ${probed}/${total}`);
          if (probed === total) stderr.write('\n');
        }
      }
    : null;

  if (command === 'iface') {
    const report = listInterfaces({ interfaces: io.interfaces });
    if (values.json) stdout.write(renderJson(report, { pretty: values.pretty }));
    else stdout.write(renderInterfaces(report, { color }));
    return EXIT.OK;
  }

  if (command === 'check') {
    const host = positional[0];
    const report = await checkHost({
      host,
      ports,
      timeout: values.timeout,
      concurrency: values.concurrency,
      arp: io.arp,
    });
    if (!report.ok) {
      stderr.write(`netpeek: ${report.error}\n`);
      return EXIT.USAGE;
    }
    if (values.json) stdout.write(renderJson(report, { pretty: values.pretty }));
    else stdout.write(renderCheck(report, { color }));
    return EXIT.OK;
  }

  // scan
  const report = await discover({
    target: positional[0] ?? null,
    interfaces: io.interfaces,
    ports,
    concurrency: values.concurrency,
    timeout: values.timeout,
    stopAtFirstOpen: !values['all-ports'],
    arp: io.arp,
    onProgress: progress,
    signal: abortSignal,
  });

  if (!report.ok) {
    stderr.write(`netpeek: ${report.error}\n`);
    return EXIT.USAGE;
  }

  if (values.json) stdout.write(renderJson(report, { pretty: values.pretty }));
  else stdout.write(renderScan(report, { color }));
  return EXIT.OK;
}
