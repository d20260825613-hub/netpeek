/**
 * Hand-written argument parser.
 *
 * Knows nothing about sockets or file systems, and never prints: it turns argv
 * into { command, values, error } plus a hint, so the CLI layer can decide how
 * to report a problem and tests can assert on the parse alone.
 *
 * Commands:
 *   scan     find live hosts on a range
 *   check    probe one host's ports
 *   iface    list the machine's interfaces
 *   help     usage
 */

export const USAGE = `netpeek — what is actually on your LAN

Usage
  netpeek scan  [target] [options]      find live hosts on a range
  netpeek check <host> [options]        probe one host's ports
  netpeek iface [options]               list this machine's interfaces

Target
  scan accepts 192.168.1.0/24, 192.168.1.10/24, or a bare /24 to use your
  own subnet. With no target, the interface holding a private IPv4 address
  is scanned.

Options
      --ports <list>      ports to probe: 22,80,443 | 1-1024 (default: a
                          curated set of 11 ports that home devices answer on)
  -c, --concurrency <n>   probes in flight (default: 128)
  -t, --timeout <ms>      per-port connect timeout (default: 400)
      --all-ports         keep probing after the first open port, so each
                          host reports every open port instead of the first
      --json              JSON output
      --pretty            indent the JSON
      --color / --no-color  force or disable ANSI colours
      --progress          print progress to stderr while scanning
  -h, --help              show this help
  -v, --version           print the version

Examples
  netpeek scan                          scan your own subnet
  netpeek scan 192.168.1.0/24           scan an explicit range
  netpeek scan 10.0.0.0/24 --ports 1-1024 --concurrency 256
  netpeek check 192.168.1.1 --ports 22,80,443
  netpeek iface --json
  netpeek scan --json > lan.json

Exit codes
  0  the scan completed
  1  the scan started and then failed
  2  the arguments were wrong, or the target cannot be scanned

Notes
  * Hosts are found with TCP connects, not ICMP: no administrator rights
    needed, and it still works where ping is filtered.
  * MAC addresses and vendors come from the OS ARP table, so they only
    appear for devices this machine has already talked to.
`;

/** Option definitions. `default` feeds the value when the flag is absent. */
const SPEC = {
  ports: { type: 'string' },
  concurrency: { type: 'number', short: 'c', default: 128, min: 1, max: 4096 },
  timeout: { type: 'number', short: 't', default: 400, min: 10, max: 60000 },
  'all-ports': { type: 'boolean', default: false },
  json: { type: 'boolean', default: false },
  pretty: { type: 'boolean', default: false },
  color: { type: 'boolean', default: undefined, negatable: true },
  progress: { type: 'boolean', default: false, negatable: true },
  help: { type: 'boolean', short: 'h', default: false },
  version: { type: 'boolean', short: 'v', default: false },
};

/**
 * Single-character aliases. Every target here must exist in SPEC — the tests
 * assert that, because a typo would otherwise surface as "unknown option" for a
 * flag the help text advertises.
 */
const ALIASES = new Map([
  ['c', 'concurrency'],
  ['t', 'timeout'],
  ['h', 'help'],
  ['v', 'version'],
]);

export const COMMANDS = ['scan', 'check', 'iface', 'help'];

export function parseArgs(argv) {
  const values = {};
  for (const [name, def] of Object.entries(SPEC)) {
    if (def.default !== undefined) values[name] = def.default;
  }

  const positional = [];
  let command = null;
  const args = [...argv];

  // The command must come first so `netpeek scan --json` and `netpeek --help`
  // are unambiguous, and so an unknown word is reported as an unknown command
  // rather than silently becoming a path.
  if (args.length > 0 && !args[0].startsWith('-')) {
    command = args.shift();
    if (!COMMANDS.includes(command)) {
      return { ok: false, command: null, message: `unknown command: ${command}`, hint: `expected one of: ${COMMANDS.join(', ')}` };
    }
  } else if (args.includes('--help') || args.includes('-h')) {
    command = 'help';
  } else if (args.includes('--version') || args.includes('-v')) {
    command = 'help';
  } else {
    return { ok: false, command: null, message: 'no command given', hint: `expected one of: ${COMMANDS.join(', ')}` };
  }

  while (args.length > 0) {
    const token = args.shift();
    if (token === '--') {
      positional.push(...args);
      break;
    }

    if (token.startsWith('--')) {
      const body = token.slice(2);
      const eq = body.indexOf('=');
      const rawName = eq === -1 ? body : body.slice(0, eq);
      const inline = eq === -1 ? null : body.slice(eq + 1);

      let name = rawName;
      let negated = false;
      if (!SPEC[name] && rawName.startsWith('no-')) {
        const bare = rawName.slice(3);
        if (SPEC[bare]?.negatable) {
          name = bare;
          negated = true;
        }
      }

      const def = SPEC[name];
      if (!def) {
        return {
          ok: false,
          command,
          message: `unknown option: --${rawName}`,
          hint: `run "netpeek help" to see every option`,
        };
      }

      if (def.type === 'boolean') {
        if (inline !== null && !/^(true|false)$/i.test(inline)) {
          return { ok: false, command, message: `--${name} is a switch`, hint: `write --${name} with no value` };
        }
        values[name] = inline === null ? !negated : inline.toLowerCase() === 'true' !== negated;
        continue;
      }

      if (negated) return { ok: false, command, message: `--no-${name} is not valid`, hint: `--${name} takes a value` };

      let value = inline;
      if (value === null) {
        if (args.length === 0) {
          return { ok: false, command, message: `option --${name} requires a value`, hint: `for example --${name} <value>` };
        }
        value = args.shift();
      }
      const problem = applyValue(values, name, def, value);
      if (problem) return { ok: false, command, ...problem };
      continue;
    }

    if (token.startsWith('-') && token !== '-') {
      const chars = [...token.slice(1)];
      let pending = null;
      for (let i = 0; i < chars.length; i += 1) {
        const mapped = ALIASES.get(chars[i]);
        if (!mapped) {
          return { ok: false, command, message: `unknown option: -${chars[i]}`, hint: 'run "netpeek help" to see every option' };
        }
        const def = SPEC[mapped];
        if (def.type === 'boolean') {
          values[mapped] = true;
          continue;
        }
        const rest = chars.slice(i + 1).join('');
        if (rest !== '') {
          const problem = applyValue(values, mapped, def, rest);
          if (problem) return { ok: false, command, ...problem };
        } else {
          pending = mapped;
        }
        break;
      }
      if (pending !== null) {
        if (args.length === 0) {
          return { ok: false, command, message: `option -${SPEC[pending].short} (--${pending}) requires a value`, hint: `for example -${SPEC[pending].short} <value>` };
        }
        const problem = applyValue(values, pending, SPEC[pending], args.shift());
        if (problem) return { ok: false, command, ...problem };
      }
      continue;
    }

    positional.push(token);
  }

  if (command === 'scan' && positional.length > 1) {
    return { ok: false, command, message: `scan takes one target, got ${positional.length}`, hint: 'quote a single CIDR, for example "192.168.1.0/24"' };
  }
  if (command === 'check' && positional.length !== 1) {
    return {
      ok: false,
      command,
      message: positional.length === 0 ? 'check needs a host' : `check takes one host, got ${positional.length}`,
      hint: 'for example: netpeek check 192.168.1.1',
    };
  }

  return { ok: true, command, values, positional };
}

/** Validate and store one option value. Returns an error object or null. */
function applyValue(values, name, def, raw) {
  switch (def.type) {
    case 'string': {
      values[name] = String(raw);
      return null;
    }
    case 'number': {
      if (!/^\d+$/.test(String(raw).trim())) {
        return { message: `--${name} expects a number, got "${raw}"`, hint: `for example --${name} ${def.min ?? 1}` };
      }
      const value = Number(raw);
      if (def.min !== undefined && value < def.min) {
        return { message: `--${name} must be >= ${def.min}`, hint: `the smallest accepted value is ${def.min}` };
      }
      if (def.max !== undefined && value > def.max) {
        return { message: `--${name} must be <= ${def.max}`, hint: `the largest accepted value is ${def.max}` };
      }
      values[name] = value;
      return null;
    }
    default:
      return { message: `internal: unhandled option type for --${name}`, hint: null };
  }
}

/** Long option names, for help output and tests. */
export const OPTION_NAMES = Object.keys(SPEC);

/** Short-to-long alias pairs, exported so a test can prove none is a typo. */
export const ALIASED_NAMES = [...ALIASES.entries()];
