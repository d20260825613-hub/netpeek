# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-15

Bug-fix release. 112 tests across 6 files, green on Node 18.17 / 20 / 22 / 24.

### Fixed

- **被中断的扫描不再被当成完整的扫描报告。** 以前 Ctrl-C 之后 `probedAddresses`
  填的是「计划扫描的地址数」，报告里没有任何中断标记，`ok` 仍为 true、退出码仍是
  0 —— 用户看到 `254/254 addresses` 却只扫了一部分。现在 `discover` 统计**真正
  完成探测**的地址数，报告里新增 `aborted` 字段、`network.plannedAddresses` 字段
  和一条 `errors` 说明，文本输出打印「scan interrupted after N of M addresses —
  results are incomplete」，CLI 以 130 退出。中断后也不再发送 ARP 唤醒用的 UDP
  包，让报告尽快返回。
- **`--ports=`（空值）不再静默改用默认端口表。** 空字符串是 falsy，因此原来的
  `if (values.ports)` 跳过了整个端口校验，用户明确写了「不要用默认端口集」却扫了
  11 个默认端口；现在按「选项未提供」与「选项值为空」分别处理，`--ports=` 报
  `netpeek: empty port list` 并以 2 退出。
- **Linux 上直读 `/proc/net/arp` 的分支终于可达。** 调用点把 `readFileSync` 传给了
  `readArpTable` 的 `run` 参数（而不是 `readFile`），三条分支的守卫全部为假，函数
  静默返回空 Map，于是每次 Linux 扫描都白起一个 `arp -an` 子进程。现在参数按名传
  递，内核表可用时完全不启动子进程。
- **4096 地址上限的提示写反了。** 原文是 "use a longer prefix to cover it all"，
  但前缀越长网段越小，而会触发这条提示的 `/8`、`/16` 用任何更长前缀都不可能覆盖。
  现在提示说明网段实际有多大、只会探测前多少个，并建议缩小网段或提高上限。
- **`check` 的 PORT 列不再错位。** 列宽固定 14 字符，`8080/http-alt`（13 字符）
  加前导空格后已经溢出，STATE 列比 `65535` 那行右移 3 列；现在列宽按本次报告里最长
  的端口标签计算，表头与每一行对齐。

### Added

- **`--limit <n>`**（默认 4096，上限 1000000）：一次扫描最多探测多少个地址。网段更
  大时只扫最前面 n 个，报告里 `truncated: true`、`network.limit` 为实际用的上限。
  库调用对应 `discover({ limit })` 与 `resolveTargets({ limit })`。
- 退出码 **130**：扫描被中断。报告照常打印（部分是部分的结果），但退出码明确表示
  「没扫完」。
- `discover` 和 `checkHost` 新增可选参数 `run`，以及 `arpTable({ readFile, run,
  directRead })`：让「Linux 上不启动子进程」这件事可以被测试证明，注入后不会真的
  发 UDP 包或起 `arp` 子进程。

### Documentation

- README 的 JSON 示例改为一次真实扫描输出的字段结构（补上 `summary.withOpenPorts`、
  `network` 的 `address`/`prefix`/`totalAddresses`/`plannedAddresses`/`truncated`/
  `limit`、`options.timeout`、`aborted`、`errors`），并写明 `--limit`、退出码 130 与
  「中断的报告长什么样」。

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

### Tests

- The test `an aborted scan still returns a report instead of throwing` asserted
  the old behaviour (exit 0 for an interrupted scan) and was rewritten: it is
  now `an aborted scan reports itself as incomplete and exits non-zero`, which
  pins exit 130, `aborted: true` and `probedAddresses < totalAddresses`. No other
  assertion was relaxed or removed.

[Unreleased]: https://github.com/d20260825613-hub/netpeek/commits/main
[0.2.0]: https://github.com/d20260825613-hub/netpeek/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/d20260825613-hub/netpeek/releases/tag/v0.1.0
