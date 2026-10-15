#!/usr/bin/env node
/**
 * Test entry point.
 *
 * `node --test test/` behaves differently across Node 18/20/22/24 — glob
 * expansion is not available on 18, and directory recursion changed in 21 — so
 * the file list is explicit here. That is the only form whose meaning is
 * identical on every supported version, and it also means a new test file has
 * to be added deliberately rather than being picked up by accident.
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const TEST_FILES = [
  'test/net.test.js',
  'test/args.test.js',
  'test/scan.test.js',
  'test/discover.test.js',
  'test/render.test.js',
  'test/cli.test.js',
];

const args = ['--test', ...TEST_FILES];
const result = spawnSync(process.execPath, args, {
  cwd: projectRoot,
  stdio: 'inherit',
});

process.exit(result.status ?? 1);
