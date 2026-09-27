#!/usr/bin/env node
/**
 * netpeek CLI entry point.
 *
 * Keeps the process-level concerns here (signals, EPIPE, exit code) so the
 * library stays free of them and remains safe to import from another program.
 */

import process from 'node:process';

import { run } from '../src/cli.js';

const controller = new AbortController();

/** Install the three handlers every CLI needs and most forget. */
function installHandlers() {
  // `netpeek scan | head` should exit quietly, not print a stack trace
  process.stdout.on('error', (error) => {
    if (error?.code === 'EPIPE') process.exit(0);
    throw error;
  });

  let interrupts = 0;
  const onSignal = (signal) => {
    interrupts += 1;
    if (interrupts === 1) {
      controller.abort();
      process.stderr.write('\nnetpeek: stopping the scan; press Ctrl-C again to exit now\n');
      return;
    }
    process.exit(130);
  };
  process.on('SIGINT', () => onSignal('SIGINT'));
  process.on('SIGTERM', () => onSignal('SIGTERM'));

  const debug = process.argv.includes('--debug') || process.env.NETPEEK_DEBUG === '1';
  process.on('uncaughtException', (error) => {
    process.stderr.write(`netpeek: unexpected error: ${error?.message ?? error}\n`);
    if (debug) process.stderr.write(`${error?.stack ?? ''}\n`);
    else process.stderr.write('  re-run with --debug for a stack trace\n');
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    process.stderr.write(`netpeek: unexpected rejection: ${reason?.message ?? reason}\n`);
    if (debug) process.stderr.write(`${reason?.stack ?? ''}\n`);
    process.exit(1);
  });
}

installHandlers();

try {
  process.exitCode = await run(process.argv.slice(2), { abortSignal: controller.signal });
} catch (error) {
  process.stderr.write(`netpeek: ${error?.message ?? error}\n`);
  process.exitCode = 1;
}
