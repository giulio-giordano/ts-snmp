/** Public SNMP client implementation. */
export { SnmpClient } from "./client/SnmpClient.ts";

/** Public SNMP types, bindings, options, and errors. */
export type {
  BaseSnmpOptions,
  Counter32,
  Counter64,
  Counter32VarBind,
  Counter64VarBind,
  ExceptionVarBind,
  Gauge32,
  Gauge32VarBind,
  IntegerVarBind,
  IpAddressVarBind,
  NullVarBind,
  ObjectIdentifierVarBind,
  OctetString,
  OctetStringVarBind,
  Oid,
  OpaqueVarBind,
  Snmp,
  SnmpOptions,
  SnmpValueType,
  SnmpVersion,
  SnmpV1Options,
  SnmpV2cOptions,
  SnmpV3Options,
  TimeTicks,
  TimeTicksVarBind,
  Unsigned32,
  VarBind,
} from "./types.ts";

/** Public errors that callers can catch and branch on. */
export { SnmpError, SnmpResponseError, SnmpTimeoutError } from "./types.ts";

/** Public SNMPv3 USM credential configuration types and algorithms. */
export type {
  AuthNoPrivOptions,
  AuthPrivOptions,
  NoAuthNoPrivOptions,
  SnmpV3SecurityOptions,
  UsmAuthProtocol,
  UsmPrivacyProtocol,
} from "./protocol/v3Security.ts";

/** Abstract UDP transport contract and default datagram implementation. */
export { DefaultUdpTransport, UdpTransport } from "./transport/UdpTransport.ts";
export type { ResponseMatcher, UdpTransportOptions } from "./transport/UdpTransport.ts";
