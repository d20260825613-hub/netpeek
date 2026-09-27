/**
 * Shared fixtures. Plain data only — no network, no filesystem — so tests that
 * depend on them stay fast and deterministic.
 */

/**
 * A plausible two-adapter machine: VirtualBox host-only plus a Wi-Fi LAN, with
 * a loopback and an IPv6 address that must never be chosen for a scan.
 */
export const SAMPLE_INTERFACES = {
  'Ethernet 2': [
    {
      family: 'IPv6',
      address: 'fe80::44ab:b66c:9b77:fda6',
      netmask: 'ffff:ffff:ffff:ffff::',
      mac: '0a:00:27:00:00:03',
      internal: false,
      cidr: 'fe80::44ab:b66c:9b77:fda6/64',
    },
    {
      family: 'IPv4',
      address: '192.168.56.1',
      netmask: '255.255.255.0',
      mac: '0a:00:27:00:00:03',
      internal: false,
      cidr: '192.168.56.1/24',
    },
  ],
  WLAN: [
    {
      family: 'IPv4',
      address: '192.168.2.108',
      netmask: '255.255.255.0',
      mac: '20:79:18:8e:0a:da',
      internal: false,
      cidr: '192.168.2.108/24',
    },
  ],
  'Loopback Pseudo-Interface 1': [
    { family: 'IPv6', address: '::1', netmask: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', mac: '00:00:00:00:00:00', internal: true, cidr: '::1/128' },
    { family: 'IPv4', address: '127.0.0.1', netmask: '255.0.0.0', mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' },
  ],
};

/** An ARP table with a known vendor, a virtual adapter and a multicast entry. */
export const SAMPLE_ARP = new Map([
  ['192.168.2.1', '20:79:18:8E:0A:DA'],
  ['192.168.2.50', '0A:00:27:00:00:03'],
  ['224.0.0.22', '01:00:5E:00:00:16'],
]);
