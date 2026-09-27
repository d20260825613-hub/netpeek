# netpeek

**回答"我的局域网里到底有什么"的零依赖命令行工具。**

一条命令扫出网段里活着的主机、开着哪些端口，并把 MAC 地址翻译成厂商名 —— 不需要管理员权限，不需要装 libpcap，不需要 Nmap。

```
$ netpeek scan
netpeek scanned 192.168.2.108/24 on WLAN — 254/254 addresses, 11 port(s), 7274 ms

  ADDRESS         OPEN PORTS                    DEVICE
  192.168.2.1     80/http (first open port)     TP-LINK TECHNOLOGIES 80:AE:54:8B:6A:57
  192.168.2.108   80/http (first open port)     this machine 20:79:18:8E:0A:DA

  seen in the ARP table but no probed port answered (6)
  192.168.2.100                                 TP-LINK TECHNOLOGIES 80:AE:54:AA:AA:AA
  192.168.2.102                                 randomised MAC 92:C8:FC:A3:15:AE

  2 live, 2 open port(s), 6 ARP-only entries
```

*上面是真实输出（本机 Wi-Fi 网段），不是示意图。*

---

## 为什么又写一个扫描器

Nmap 无可替代，但它对一个日常问题太重了：**"刚才路由器上插的那个东西，IP 是多少？"**

netpeek 的取舍：

| | netpeek | Nmap |
| --- | --- | --- |
| 安装 | `npx netpeek` 或单个文件，零依赖 | 需要安装，Windows 还要装 Npcap |
| 权限 | 普通用户 | 部分扫描模式需要 root/Administrator |
| 主机发现 | TCP connect | ICMP / ARP / TCP / 半开连接 |
| 端口状态 | open / closed / filtered | 更细，且能识别服务版本 |
| 输出 | 表格或 JSON | 极其丰富 |

它不做服务指纹、不做漏洞脚本、不做半开扫描。它做的是"扫一遍家里网络，告诉我有什么"。

## 安装

```bash
npx netpeek scan          # 不安装直接跑
npm install -g netpeek    # 或全局安装
```

要求 **Node ≥ 18.17**，无任何运行时依赖。

## 用法

```bash
netpeek scan                          # 扫本机所在网段
netpeek scan 192.168.1.0/24           # 扫指定网段
netpeek scan /28                      # 只给前缀：用本机地址 + /28
netpeek scan 10.0.0.0/24 --ports 1-1024 --concurrency 256
netpeek scan --all-ports              # 每台主机列出所有开放端口
netpeek check 192.168.1.1             # 只看一台主机
netpeek check 192.168.1.1 --ports 22,80,443,3389
netpeek iface                         # 本机有哪些网卡和地址
netpeek scan --json --pretty          # 给程序消费
```

### 选项

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `--ports <list>` | 11 个常见端口 | `22,80,443` 或 `1-1024` |
| `-c, --concurrency <n>` | 128 | 并发探测数 |
| `-t, --timeout <ms>` | 400 | 单端口连接超时 |
| `--all-ports` | 关 | 命中第一个开放端口后继续探测，列出全部 |
| `--json` / `--pretty` | 关 | JSON 输出 / 缩进 |
| `--progress` | 关 | 进度写 stderr（不污染 stdout） |
| `--no-color` | 自动 | 关闭 ANSI 颜色，也认 `NO_COLOR` |

### 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 扫描完成（即使一台主机都没发现） |
| 1 | 扫描开始后失败 |
| 2 | 参数非法，或给的网段不可扫描 |

## 它怎么判断"活着"

**用 TCP connect，不用 ICMP。** 两个原因：

1. **不需要管理员权限。** raw socket 发 ICMP 要 root / Administrator，一个日常小工具不该要这个。
2. **防火墙通常放行 TCP 不放行 ping。** 大量设备默认丢弃 echo request，用 ping 扫描会漏掉它们。

代价是：**只在默认端口集里有开放端口的主机才会被列出**。一台全端口过滤、或者当时在睡眠的设备，netpeek 看不到它 —— 这是 TCP 探测的固有局限，不是 bug。发现不了的东西不会假装发现。

一次 `connect()` 有三种结果，netpeek 区分对待：

| 结果 | 含义 | 算"活着"吗 |
| --- | --- | --- |
| `open` | 有服务在监听 | **是** |
| `closed`（连接被拒绝） | 地址可达，但没有监听 | **否** |
| `filtered`（无响应） | 什么都证明不了：可能是丢包 | **否** |

`closed` 不算活着是刻意的：在跨网段的路由环境里，拒绝连接的可能是路由器，把所有拒绝都当主机会让一份报告全是假阳性。

## MAC 地址和厂商是怎么来的

来自操作系统的 **ARP 表**，不抓包、不发 ARP 请求，所以完全不需要特权。

这里有两个实际会踩的坑，都已经处理：

**1. ARP 表可能一开始是空的。** Windows 的 ARP 条目几分钟就过期，而一台"只是被 listen 过"的主机根本不会产生条目。所以 netpeek 在扫描后会向每个地址发一个 UDP 空包（目标是没人监听的 9 端口）—— 这没有任何协议副作用，但会强制内核先解析链路层地址。就是这一个 UDP 包，把"unknown vendor"变成真实 MAC。

**2. `arp -a` 的输出是本地化的。** 中文版 Windows 打的是 `动态`/`静态` 而不是 `dynamic`/`static`。最初的实现按英文关键字过滤，结果在中文系统上**每一条都被丢掉**，所有设备都显示 unknown 且没有任何报错提示。现在解析只认行的结构（IPv4 字面量 + 六个十六进制对），与语言无关。

厂商名来自内置的 OUI 表（约 270 条），覆盖家用网络里真正会出现的设备。**表里没有的就不猜**，显示 `unknown vendor` 并保留原始 MAC，方便你自己去查。虚拟网卡和手机会有随机 MAC（本地管理位被置位），这些会标成 `randomised MAC` 而不是硬套一个厂商名。

## JSON 输出

```bash
netpeek scan --json --pretty > lan.json
```

```jsonc
{
  "ok": true,
  "tool": { "name": "netpeek", "version": "0.1.0" },
  "network": { "cidr": "192.168.2.108/24", "interface": "WLAN", "probedAddresses": 254 },
  "options": { "ports": [22, 23, 53], "concurrency": 128, "stopAtFirstOpen": true },
  "summary": { "alive": 2, "arpOnly": 6, "openPortTotal": 2 },
  "hosts": [
    { "address": "192.168.2.1", "openPorts": [{ "port": 80, "service": "http", "ms": 29.1 }],
      "mac": "80:AE:54:8B:6A:57", "vendor": "TP-LINK TECHNOLOGIES", "deviceKind": "device" }
  ],
  "arpOnly": [
    { "address": "192.168.2.102", "openPorts": null, "mac": "92:C8:FC:A3:15:AE",
      "vendor": null, "deviceKind": "randomised", "deviceNote": "locally administered address…" }
  ]
}
```

`hosts` 是**探测到有开放端口**的主机；`arpOnly` 是只在 ARP 表里出现、探测端口都没应答的设备。两者分开，是因为它们的确信度不同 —— 混在一张表里会让"活着"这个词失去意义。

## 作为库使用

```js
import { discover, checkHost, probePort, parseTarget, hostsInRange } from 'netpeek';

const report = await discover({ target: '192.168.1.0/24', ports: [{ port: 80 }] });
for (const host of report.hosts) console.log(host.address, host.vendor);

// 单端口探测，永不抛异常：refused 是正常答案，不是错误
const result = await probePort('192.168.1.1', 443, { timeout: 500 });
// { host, port, status: 'open'|'closed'|'timeout'|'unreachable', ms, error }
```

网段展开是纯函数，不需要网络，也不受 4096 个地址的默认上限影响：

```js
hostsInRange('10.0.0.0', 8, { limit: 100000 });  // -> 100000 个地址，并标记 truncated
```

## 已知边界

- **只支持 IPv4。** IPv6 邻居发现和地址枚举完全是另一套东西，混在一起会让这个工具变得难懂。
- **不做名称解析。** 不查 DNS、不做 mDNS/NetBIOS 反查。一个会发网络请求的扫描器应该在参数里明确说明这一点，而不是偷偷发。
- **厂商表是子集。** 约 270 条常见的。查不到就报 unknown，见上。
- **`/24` 扫描约 7 秒**（11 个端口、超时 400ms、并发 128）。要更快就减少端口数或降低超时；`--all-ports` 会明显变慢。

## 开发

```bash
npm test        # 91 个用例，含真实 loopback socket 的端到端探测
npm run check   # 语法检查 + 测试
```

测试分两层：纯函数（网段运算、ARP 解析、OUI 匹配、参数解析）用固定输入断言；探测层**开真实 socket**，因为一个 mock 过的 `connect()` 只能证明 mock 自己是对的。

## 许可

MIT
