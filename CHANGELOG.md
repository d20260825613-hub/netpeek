# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-27

First release. 91 tests across 5 files, green on Node 18.17 / 20 / 22 / 24.

### Added

- **`netpeek scan [target]`**: find live hosts on a range. Accepts
  `192.168.1.0/24`, `192.168.1.10/24`, a bare `/28` (using this machine's own
  address), or nothing at all, which scans the interface holding a private IPv4
  address.
- **`netpeek check <host>`**: probe one host and report every port's state
  separately — `open`, `closed (refused)`, and `no answer` are different answers
  and the report keeps them apart.
- **`netpeek iface`**: list this machine's addresses, and say which one a bare
  `scan` would use.
- Host discovery by **TCP connect rather than ICMP**: no Administrator rights,
  and it still works on hosts that drop echo requests.
- Device identification from the OS **ARP table**, with an OUI vendor table of
  about 270 common prefixes. Unknown prefixes are reported as unknown rather
  than guessed, and locally administered (randomised/virtual) addresses are
  labelled as such.
- A **UDP nudge** before reading the ARP table. A Windows ARP entry expires in
  minutes and a host that was only listened to never had one, so the table is
  often empty right after a scan; one datagram to a closed port forces the
  kernel to resolve the link-layer address.
- Text output for a terminal and `--json` for a program, with progress on stderr
  so a redirected report is never corrupted.
- Library API: `discover`, `checkHost`, `probePort`, `parsePorts`,
  `hostsInRange`, `parseTarget`, `pickInterface`, `vendorFor`, `mapPool`.
- Zero runtime dependencies. Requires Node >= 18.17 (no `findLast`, no
  `Object.groupBy`, no JSON imports).

### Fixed during development

Recorded because each one was only visible by running the tool for real, and the
tests now pin them:

- `parseWindowsArp` required the literal words `static`/`dynamic` in the type
  column, so on a **localised Windows** (which prints `动态`/`静态`) every row
  was discarded and all devices were reported as unknown vendors with no
  indication that parsing had failed. It now matches the row's shape only.
- `defaultRunner` launched `cmd` with an empty argument vector, which opens an
  interactive shell that never exits — the first real scan hung forever.
- `resolveTargets` picked the first non-internal IPv4 interface, so on a machine
  with a VirtualBox host-only adapter (enumerated first) a bare `scan` silently
  probed `192.168.56.0/24` instead of the real Wi-Fi LAN. Interfaces are now
  scored, with known virtual adapter names and host-only ranges penalised.
- `hostsInRange` reported the whole subnet size as `total` instead of the usable
  host count, which made the truncation note and progress output wrong.
- The CLI's abort signal was read from `io.signal`, a key tests also use to
  inject fixtures; a test harness doing so turned every command into
  "unknown option". Renamed to `io.abortSignal`.
- `--version` printed the help text and exited 2, because the help branch ran
  first and both flags parse to the same command name.

[Unreleased]: https://github.com/d20260825613-hub/netpeek/commits/main
[0.1.0]: https://github.com/d20260825613-hub/netpeek/releases/tag/v0.1.0
