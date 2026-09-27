/**
 * Library entry point. Everything reachable from here is supported API; the
 * CLI is a thin wrapper over it, so both front ends behave identically.
 */

export {
  VERSION,
  checkHost,
  defaultPorts,
  describeDevice,
  discover,
  listInterfaces,
  parsePorts,
  resolveTargets,
} from './discover.js';

export {
  ipToInt,
  intToIp,
  isIPv4,
  netmaskToPrefix,
  networkBounds,
  hostsInRange,
  parseTarget,
  pickInterface,
  prefixForAddress,
  prefixToInt,
  scoreInterface,
} from './net.js';

export {
  COMMON_PORTS,
  arpTable,
  mapPool,
  parseBsdArp,
  parseProcNetArp,
  parseWindowsArp,
  probePort,
  serviceName,
} from './scan.js';

export { OUI_VENDORS, isGroupAddress, isLocallyAdministered, normalizeMac, vendorFor } from './mac.js';

export { renderCheck, renderInterfaces, renderJson, renderScan, shouldUseColor } from './reporter.js';

export { EXIT, run } from './cli.js';
export { OPTION_NAMES, USAGE, parseArgs } from './args.js';
