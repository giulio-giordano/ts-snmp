import type { SnmpV3SecurityOptions } from "./protocol/v3Security.ts";

/** Dotted-decimal representation of an SNMP object identifier. */
export type Oid = string;

/** Raw bytes used for OCTET STRING and Opaque values. */
export type OctetString = Uint8Array;

/** JavaScript numeric representation of SNMP INTEGER values. */
export type SnmpInteger = number;

/** JavaScript numeric representation shared by Gauge32 and Unsigned32. */
export type Gauge32 = number;

/** Alias for Gauge32, the SMIv2 name for the same application tag. */
export type Unsigned32 = Gauge32;

/** JavaScript numeric representation of Counter32 values. */
export type Counter32 = number;

/** JavaScript numeric representation of TimeTicks values. */
export type TimeTicks = number;

/** BigInt representation preserves the full range of Counter64 values. */
export type Counter64 = bigint;

/** The SNMP variable syntax carried by a decoded OID binding. */
export type SnmpValueType =
  | "INTEGER"
  | "OCTET_STRING"
  | "OBJECT_IDENTIFIER"
  | "NULL"
  | "IP_ADDRESS"
  | "COUNTER32"
  | "GAUGE32"
  | "TIME_TICKS"
  | "OPAQUE"
  | "COUNTER64"
  | "NO_SUCH_OBJECT"
  | "NO_SUCH_INSTANCE"
  | "END_OF_MIB_VIEW";

/** Typed binding for an SNMP INTEGER value. */
export interface IntegerVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "INTEGER";
  /** Signed integer value. */
  value: SnmpInteger;
}

/** Typed binding for an SNMP OCTET STRING value. */
export interface OctetStringVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "OCTET_STRING";
  /** Raw bytes; callers can decode text using their required character encoding. */
  value: OctetString;
}

/** Typed binding for an SNMP OBJECT IDENTIFIER value. */
export interface ObjectIdentifierVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "OBJECT_IDENTIFIER";
  /** Dotted-decimal OID value. */
  value: Oid;
}

/** Typed binding for an SNMP NULL value. */
export interface NullVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "NULL";
  /** NULL values have no payload. */
  value: null;
}

/** Typed binding for an SNMP IpAddress value. */
export interface IpAddressVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "IP_ADDRESS";
  /** IPv4 address in dotted-decimal form. */
  value: string;
}

/** Typed binding for an SNMP Counter32 value. */
export interface Counter32VarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "COUNTER32";
  /** Unsigned 32-bit counter. */
  value: Counter32;
}

/** Typed binding for Gauge32 or Unsigned32 (the same application tag). */
export interface Gauge32VarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "GAUGE32";
  /** Unsigned 32-bit gauge/unsigned value. */
  value: Gauge32;
}

/** Typed binding for an SNMP TimeTicks value. */
export interface TimeTicksVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "TIME_TICKS";
  /** Hundredths of a second since the relevant management epoch. */
  value: TimeTicks;
}

/** Typed binding for an SNMP Opaque value. */
export interface OpaqueVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "OPAQUE";
  /** Raw opaque bytes. */
  value: OctetString;
}

/** Typed binding for an SNMP Counter64 value. */
export interface Counter64VarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Wire syntax decoded from BER. */
  type: "COUNTER64";
  /** Unsigned 64-bit counter. */
  value: Counter64;
}

/** Typed binding for SNMP exception values that carry no payload. */
export interface ExceptionVarBind {
  /** OID whose value is represented by this binding. */
  oid: Oid;
  /** Exception syntax returned by an SNMP agent. */
  type: "NO_SUCH_OBJECT" | "NO_SUCH_INSTANCE" | "END_OF_MIB_VIEW";
  /** Exception values have no payload. */
  value: null;
}

/** Discriminated union of all SNMP OID/value binding syntaxes. */
export type VarBind =
  | IntegerVarBind
  | OctetStringVarBind
  | ObjectIdentifierVarBind
  | NullVarBind
  | IpAddressVarBind
  | Counter32VarBind
  | Gauge32VarBind
  | TimeTicksVarBind
  | OpaqueVarBind
  | Counter64VarBind
  | ExceptionVarBind;

/** SNMP message version supported by this library. */
export type SnmpVersion = "v1" | "v2c" | "v3";

/** Common network and retry configuration for a UDP SNMP client. */
export interface BaseSnmpOptions {
  /** DNS name or IP address of the SNMP agent. */
  host: string;
  /** UDP port; defaults to the standard SNMP port 161. */
  port?: number;
  /** Per-request timeout in milliseconds; defaults to 1000. */
  timeoutMs?: number;
  /** Number of retries after the initial request; defaults to 1. */
  retries?: number;
}

/** SNMPv1 client configuration. */
export interface SnmpV1Options extends BaseSnmpOptions {
  /** Selects SNMPv1 message and PDU behavior. */
  version: "v1";
  /** SNMPv1 community name. */
  community: string;
}

/** SNMPv2c client configuration. */
export interface SnmpV2cOptions extends BaseSnmpOptions {
  /** Selects SNMPv2c message and PDU behavior. */
  version: "v2c";
  /** SNMPv2c community name. */
  community: string;
}

/** SNMPv3 client configuration using the User-based Security Model. */
export interface SnmpV3Options extends BaseSnmpOptions {
  /** Selects SNMPv3 message and USM processing. */
  version: "v3";
  /** User-based Security Model username and security-level credentials. */
  security: SnmpV3SecurityOptions;
  /** Optional context name; defaults to the empty context. */
  contextName?: string;
}

/** Configuration accepted by the public SNMP client implementation. */
export type SnmpOptions = SnmpV1Options | SnmpV2cOptions | SnmpV3Options;

/** Public operations implemented by the SNMP client. */
export interface Snmp {
  /** Read one OID and return its typed value binding. */
  get(oid: Oid): Promise<VarBind>;
  /** Walk an OID subtree, yielding each typed binding as it is received. */
  walk(rootOid: Oid): AsyncIterable<VarBind>;
  /** Close the underlying UDP socket and release transport resources. */
  close(): Promise<void>;
}

/** Base error for failures reported by the SNMP library. */
export class SnmpError extends Error {
  /** Stable machine-readable category for the failure. */
  readonly code: string;

  /** Create an error with a stable code and optional underlying cause. */
  constructor(message: string, code: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SnmpError";
    this.code = code;
  }
}

/** Error raised when no response arrives within configured retries. */
export class SnmpTimeoutError extends SnmpError {
  /** Create a timeout error for the requested OID or operation. */
  constructor(message: string) {
    super(message, "SNMP_TIMEOUT");
    this.name = "SnmpTimeoutError";
  }
}

/** Error returned by an agent in the SNMP response PDU. */
export class SnmpResponseError extends SnmpError {
  /** Agent's numeric SNMP error-status value. */
  readonly status: number;
  /** One-based index of the failing binding, or zero when unspecified. */
  readonly index: number;

  /** Create a response error with the PDU status and index. */
  constructor(message: string, status: number, index: number) {
    super(message, "SNMP_RESPONSE_ERROR");
    this.name = "SnmpResponseError";
    this.status = status;
    this.index = index;
  }
}
