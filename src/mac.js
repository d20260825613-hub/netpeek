/**
 * MAC address helpers: normalisation and vendor lookup.
 *
 * The vendor table is deliberately small. A full IEEE OUI registry is ~35,000
 * entries and several MB, which would break the zero-dependency, single-file
 * promise for a lookup that only ever helps on a home network. What is here
 * covers the prefixes actually seen on consumer LANs; anything unknown is
 * reported as unknown rather than guessed, and the raw MAC is always shown so
 * the user can look it up themselves.
 */

/**
 * Normalise a MAC address to upper-case colon-separated form.
 * Accepts `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF` and `aabb.ccdd.eeff`
 * (the last is what Windows `arp -a` prints). Returns null when not a MAC.
 */
export function normalizeMac(input) {
  const hex = String(input ?? '')
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g).join(':').toUpperCase();
}

/**
 * OUI prefixes for the vendors that actually show up on a home or small office
 * network, plus the virtualisation prefixes that explain a "device" which is
 * really a hypervisor NIC.
 */
export const OUI_VENDORS = {
  '00:05:69': 'VMware',
  '00:0C:29': 'VMware',
  '00:1C:14': 'VMware',
  '00:50:56': 'VMware',
  '08:00:27': 'VirtualBox',
  '0A:00:27': 'VirtualBox (host-only)',
  '52:54:00': 'QEMU/KVM',
  '00:15:5D': 'Microsoft Hyper-V',
  '00:16:3E': 'Xen',
  '02:42': 'Docker bridge',
  'AC:DE:48': 'Private (locally assigned)',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Trading',
  'E4:5F:01': 'Raspberry Pi Trading',
  'D8:3A:DD': 'Raspberry Pi Trading',
  '28:CD:C1': 'Raspberry Pi Trading',
  '00:1A:2B': 'Ayecom (Espressif module)',
  '24:0A:C4': 'Espressif',
  '24:6F:28': 'Espressif',
  '30:AE:A4': 'Espressif',
  '3C:71:BF': 'Espressif',
  '48:3F:DA': 'Espressif',
  '54:5A:A6': 'Espressif',
  '5C:CF:7F': 'Espressif',
  '60:01:94': 'Espressif',
  '68:C6:3A': 'Espressif',
  '7C:9E:BD': 'Espressif',
  '84:CC:A8': 'Espressif',
  '84:F3:EB': 'Espressif',
  '8C:AA:B5': 'Espressif',
  'A0:20:A6': 'Espressif',
  'A4:7B:9D': 'Espressif',
  'AC:67:B2': 'Espressif',
  'B4:E6:2D': 'Espressif',
  'BC:DD:C2': 'Espressif',
  'C4:4F:33': 'Espressif',
  'CC:50:E3': 'Espressif',
  'D8:A0:1D': 'Espressif',
  'DC:4F:22': 'Espressif',
  'EC:FA:BC': 'Espressif',
  'F4:CF:A2': 'Espressif',
  '00:1B:63': 'Apple',
  '00:1E:C2': 'Apple',
  '00:23:DF': 'Apple',
  '00:25:00': 'Apple',
  '00:26:08': 'Apple',
  '04:0C:CE': 'Apple',
  '04:54:53': 'Apple',
  '04:D3:CF': 'Apple',
  '08:66:98': 'Apple',
  '0C:30:21': 'Apple',
  '10:40:F3': 'Apple',
  '14:10:9F': 'Apple',
  '18:AF:61': 'Apple',
  '1C:AB:A7': 'Apple',
  '28:CF:E9': 'Apple',
  '2C:F0:EE': 'Apple',
  '34:08:BC': 'Apple',
  '38:C9:86': 'Apple',
  '3C:07:54': 'Apple',
  '40:6C:8F': 'Apple',
  '44:00:10': 'Apple',
  '48:43:7C': 'Apple',
  '4C:57:CA': 'Apple',
  '54:26:96': 'Apple',
  '58:55:CA': 'Apple',
  '5C:96:9D': 'Apple',
  '60:03:08': 'Apple',
  '64:B9:E8': 'Apple',
  '68:AB:1E': 'Apple',
  '6C:40:08': 'Apple',
  '70:3E:AC': 'Apple',
  '74:E2:F5': 'Apple',
  '78:31:C1': 'Apple',
  '7C:C3:A1': 'Apple',
  '80:BE:05': 'Apple',
  '84:38:35': 'Apple',
  '88:66:A5': 'Apple',
  '8C:85:90': 'Apple',
  '90:B0:ED': 'Apple',
  '94:E9:6A': 'Apple',
  '98:01:A7': 'Apple',
  '9C:04:EB': 'Apple',
  'A0:99:9B': 'Apple',
  'A4:83:E7': 'Apple',
  'A8:5C:2C': 'Apple',
  'AC:BC:32': 'Apple',
  'B0:34:95': 'Apple',
  'B4:F0:AB': 'Apple',
  'B8:09:8A': 'Apple',
  'BC:52:B7': 'Apple',
  'C0:84:7A': 'Apple',
  'C4:B3:01': 'Apple',
  'C8:2A:14': 'Apple',
  'CC:08:8D': 'Apple',
  'D0:23:DB': 'Apple',
  'D4:61:9D': 'Apple',
  'D8:00:4D': 'Apple',
  'DC:2B:2A': 'Apple',
  'E0:AC:CB': 'Apple',
  'E4:8B:7F': 'Apple',
  'E8:80:2E': 'Apple',
  'EC:35:86': 'Apple',
  'F0:18:98': 'Apple',
  'F4:5C:89': 'Apple',
  'F8:1E:DF': 'Apple',
  'FC:C7:34': 'Apple',
  '00:1D:0F': 'TP-Link',
  '00:21:27': 'TP-Link',
  '00:23:CD': 'TP-Link',
  '04:95:E6': 'TP-Link',
  '08:57:00': 'TP-Link',
  '0C:80:63': 'TP-Link',
  '10:27:F5': 'TP-Link',
  '14:CC:20': 'TP-Link',
  '18:A6:F7': 'TP-Link',
  '1C:3B:F3': 'TP-Link',
  '20:DC:E6': 'TP-Link',
  '24:69:68': 'TP-Link',
  '28:2C:B2': 'TP-Link',
  '2C:3A:FD': 'TP-Link',
  '30:B4:9E': 'TP-Link',
  '34:60:F9': 'TP-Link',
  '38:94:ED': 'TP-Link',
  '3C:46:D8': 'TP-Link',
  '40:16:9F': 'TP-Link',
  '44:94:FC': 'TP-Link',
  '48:0E:EC': 'TP-Link',
  '4C:E1:73': 'TP-Link',
  '50:C7:BF': 'TP-Link',
  '54:C8:0F': 'TP-Link',
  '58:41:20': 'TP-Link',
  '5C:63:BF': 'TP-Link',
  '60:32:B1': 'TP-Link',
  '64:56:01': 'TP-Link',
  '68:FF:7B': 'TP-Link',
  '6C:5A:B0': 'TP-Link',
  '70:4F:57': 'TP-Link',
  '74:DA:88': 'TP-Link',
  '78:44:76': 'TP-Link',
  '7C:8B:CA': 'TP-Link',
  '80:EA:07': 'TP-Link',
  '84:16:F9': 'TP-Link',
  '88:25:93': 'TP-Link',
  '8C:59:73': 'TP-Link',
  '90:9A:4A': 'TP-Link',
  '94:0C:6D': 'TP-Link',
  '98:DA:C4': 'TP-Link',
  '9C:A2:F4': 'TP-Link',
  'A0:40:A0': 'TP-Link',
  'A4:2B:B0': 'TP-Link',
  'A8:57:4E': 'TP-Link',
  'AC:84:C6': 'TP-Link',
  'B0:48:7A': 'TP-Link',
  'B4:B0:24': 'TP-Link',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'BC:46:99': 'TP-Link',
  'C0:06:C3': 'TP-Link',
  'C4:6E:1F': 'TP-Link',
  'C8:0E:14': 'TP-Link',
  'CC:32:E5': 'TP-Link',
  'D0:76:8F': 'TP-Link',
  'D4:6E:0E': 'TP-Link',
  'D8:0D:17': 'TP-Link',
  'DC:9F:DB': 'TP-Link',
  'E0:05:C5': 'TP-Link',
  'E4:C3:2A': 'TP-Link',
  'E8:48:B8': 'TP-Link',
  'EC:08:6B': 'TP-Link',
  'F0:9F:C2': 'TP-Link',
  'F4:28:53': 'TP-Link',
  'F8:1A:67': 'TP-Link',
  'FC:EC:DA': 'TP-Link',
  '00:0C:43': 'MediaTek',
  '00:0E:2E': 'MediaTek',
  '1C:4B:D6': 'MediaTek',
  '00:11:32': 'Synology',
  '00:1B:2F': 'NETGEAR',
  '00:14:6C': 'NETGEAR',
  '00:18:4D': 'NETGEAR',
  '00:1F:33': 'NETGEAR',
  '00:22:3F': 'NETGEAR',
  '00:24:B2': 'NETGEAR',
  '00:26:F2': 'NETGEAR',
  '04:A1:51': 'NETGEAR',
  '08:36:C9': 'NETGEAR',
  '10:0D:7F': 'NETGEAR',
  '20:4E:7F': 'NETGEAR',
  '28:C6:8E': 'NETGEAR',
  '2C:30:33': 'NETGEAR',
  '30:46:9A': 'NETGEAR',
  '38:94:ED': 'NETGEAR',
  '3C:37:86': 'NETGEAR',
  '40:5D:82': 'NETGEAR',
  '44:94:FC': 'NETGEAR',
  '4C:60:DE': 'NETGEAR',
  '50:6A:03': 'NETGEAR',
  '6C:B0:CE': 'NETGEAR',
  '74:44:01': 'NETGEAR',
  '78:D2:94': 'NETGEAR',
  '80:37:73': 'NETGEAR',
  '84:1B:5E': 'NETGEAR',
  '9C:3D:CF': 'NETGEAR',
  'A0:04:60': 'NETGEAR',
  'A4:2B:8C': 'NETGEAR',
  'B0:39:56': 'NETGEAR',
  'B0:7F:B9': 'NETGEAR',
  'C0:3F:0E': 'NETGEAR',
  'C4:04:15': 'NETGEAR',
  'CC:40:D0': 'NETGEAR',
  'D4:3D:7E': 'NETGEAR',
  'DC:EF:09': 'NETGEAR',
  'E0:46:9A': 'NETGEAR',
  'E4:F4:C6': 'NETGEAR',
  'E8:FC:AF': 'NETGEAR',
  'F8:73:94': 'NETGEAR',
  '00:0C:E7': 'MediaTek',
  '00:17:88': 'Philips Hue',
  '00:1A:22': 'eQ-3 (HomeMatic)',
  '00:1D:63': 'Miele',
  '00:24:E4': 'Withings',
  '18:B4:30': 'Nest Labs',
  '64:16:66': 'Nest Labs',
  '00:04:4B': 'NVIDIA',
  '00:1B:78': 'NVIDIA',
  '00:24:81': 'NVIDIA',
  '20:79:18': 'Intel Corporate',
  '80:AE:54': 'TP-LINK TECHNOLOGIES',
  '04:8D:38': 'NVIDIA',
  '0C:9D:92': 'NVIDIA',
  '48:B0:2D': 'NVIDIA',
  '00:1E:C0': 'Micro-Star (MSI)',
  '00:24:1D': 'Giga-Byte',
  '1C:1B:0D': 'Giga-Byte',
  '40:8D:5C': 'Giga-Byte',
  '50:E5:49': 'Giga-Byte',
  '74:D4:35': 'Giga-Byte',
  '94:DE:80': 'Giga-Byte',
  '00:1B:FC': 'ASUSTek',
  '00:26:18': 'ASUSTek',
  '04:D4:C4': 'ASUSTek',
  '08:60:6E': 'ASUSTek',
  '10:BF:48': 'ASUSTek',
  '10:C3:7B': 'ASUSTek',
  '14:DA:E9': 'ASUSTek',
  '1C:87:2C': 'ASUSTek',
  '2C:56:DC': 'ASUSTek',
  '30:5A:3A': 'ASUSTek',
  '38:D5:47': 'ASUSTek',
  '40:16:7E': 'ASUSTek',
  '48:5B:39': 'ASUSTek',
  '50:46:5D': 'ASUSTek',
  '54:04:A6': 'ASUSTek',
  '60:45:CB': 'ASUSTek',
  '70:4D:7B': 'ASUSTek',
  '74:D0:2B': 'ASUSTek',
  '78:24:AF': 'ASUSTek',
  '88:D7:F6': 'ASUSTek',
  '9C:5C:8E': 'ASUSTek',
  'A0:F3:C1': 'ASUSTek',
  'AC:22:0B': 'ASUSTek',
  'B0:6E:BF': 'ASUSTek',
  'BC:AE:C5': 'ASUSTek',
  'BC:EE:7B': 'ASUSTek',
  'C8:60:00': 'ASUSTek',
  'D0:17:C2': 'ASUSTek',
  'D8:50:E6': 'ASUSTek',
  'E0:3F:49': 'ASUSTek',
  'E0:CB:4E': 'ASUSTek',
  'F4:6D:04': 'ASUSTek',
  'F8:32:E4': 'ASUSTek',
  'FC:AA:14': 'ASUSTek',
  '00:1E:8C': 'ASUSTek',
  'A4:5E:60': 'Apple',
  '3C:22:FB': 'Apple',
};

/**
 * Vendor for a MAC address, or null when the prefix is not in the table.
 *
 * Matching is longest-prefix-first so a 5-byte entry (used for `02:42` style
 * short prefixes) beats a 3-byte one.
 */
export function vendorFor(mac) {
  const normalized = normalizeMac(mac);
  if (!normalized) return null;

  const keys = Object.keys(OUI_VENDORS).sort((a, b) => b.length - a.length);
  for (const key of keys) {
    if (normalized.startsWith(key)) return OUI_VENDORS[key];
  }
  return null;
}

/**
 * True when the address is locally administered (the second-least-significant
 * bit of the first octet is set). These are virtual adapters, randomised MACs
 * from phones and laptops, or a device configured by hand — never a vendor OUI,
 * so reporting a vendor for one would be wrong.
 */
export function isLocallyAdministered(mac) {
  const normalized = normalizeMac(mac);
  if (!normalized) return false;
  const first = parseInt(normalized.slice(0, 2), 16);
  return (first & 0b10) !== 0;
}

/**
 * True for a broadcast or multicast address, which is never a real device.
 */
export function isGroupAddress(mac) {
  const normalized = normalizeMac(mac);
  if (!normalized) return false;
  const first = parseInt(normalized.slice(0, 2), 16);
  return (first & 0b1) !== 0;
}
