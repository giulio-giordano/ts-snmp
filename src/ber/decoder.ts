import type { Oid, SnmpValueType, VarBind } from "../types.ts";

/** A decoded BER item and offsets into the original byte buffer. */
export interface BerTlv {
  /** BER tag octet. */
  tag: number;
  /** View containing only the encoded item's value bytes. */
  value: Uint8Array;
  /** Offset of the first value byte relative to the input buffer. */
  valueOffset: number;
  /** Offset of the first byte after this item. */
  nextOffset: number;
}

/** Decoded community-based SNMP message. */
export interface CommunityMessage {
  /** SNMP protocol version encoded on the wire: 0 for v1, 1 for v2c. */
  version: 0 | 1;
  /** Community string from the message. */
  community: string;
  /** Decoded PDU. */
  pdu: DecodedPdu;
}

/** Decoded common SNMP PDU fields. */
export interface DecodedPdu {
  /** Context-specific PDU tag. */
  tag: number;
  /** Request identifier used to correlate the response. */
  requestId: number;
  /** Error status, or GETBULK non-repeaters for request PDUs. */
  firstField: number;
  /** Error index, or GETBULK max-repetitions for request PDUs. */
  secondField: number;
  /** PDU variable bindings. */
  bindings: VarBind[];
}

/** Read one BER item and reject indefinite, truncated, or malformed lengths. */
export function readTlv(bytes: Uint8Array, offset = 0): BerTlv {
  if (offset < 0 || offset + 2 > bytes.length) throw new RangeError("Truncated BER tag or length");
  const tag = bytes[offset]!;
  let cursor = offset + 1;
  const firstLengthByte = bytes[cursor++]!;
  let length: number;

  if ((firstLengthByte & 0x80) === 0) {
    length = firstLengthByte;
  } else {
    const lengthByteCount = firstLengthByte & 0x7f;
    if (lengthByteCount === 0) throw new TypeError("Indefinite BER lengths are not supported");
    if (lengthByteCount > 4 || cursor + lengthByteCount > bytes.length) {
      throw new RangeError("Invalid or truncated BER length");
    }
    length = 0;
    for (let index = 0; index < lengthByteCount; index++) {
      length = length * 256 + bytes[cursor++]!;
    }
    if (!Number.isSafeInteger(length)) throw new RangeError("BER item is too large");
  }

  const nextOffset = cursor + length;
  if (nextOffset > bytes.length) throw new RangeError("Truncated BER value");
  return { tag, value: bytes.subarray(cursor, nextOffset), valueOffset: cursor, nextOffset };
}

/** Decode a signed BER INTEGER value into a BigInt. */
export function decodeIntegerValue(bytes: Uint8Array): bigint {
  if (bytes.length === 0) throw new TypeError("BER INTEGER cannot be empty");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  if ((bytes[0]! & 0x80) !== 0) value -= 1n << BigInt(bytes.length * 8);
  return value;
}

/** Decode a non-negative BER integer into a BigInt. */
export function decodeUnsignedValue(bytes: Uint8Array): bigint {
  if (bytes.length === 0) throw new TypeError("Unsigned BER integer cannot be empty");
  if ((bytes[0]! & 0x80) !== 0) throw new TypeError("Unsigned BER integer has its sign bit set");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** Decode a complete community-based SNMP message. */
export function decodeCommunityMessage(bytes: Uint8Array): CommunityMessage {
  const outer = readTlv(bytes);
  expectTag(outer, 0x30, "SNMP message");
  assertConsumed(bytes, outer.nextOffset);

  const fields = readChildren(outer.value);
  if (fields.length !== 3) throw new TypeError("SNMP community message must have three fields");
  const versionValue = decodeIntegerTlv(fields[0]!, "message version");
  if (versionValue !== 0n && versionValue !== 1n) throw new TypeError(`Unsupported community version: ${versionValue}`);
  expectTag(fields[1]!, 0x04, "community string");
  const pduTlv = fields[2]!;
  return {
    version: Number(versionValue) as 0 | 1,
    community: new TextDecoder().decode(fields[1]!.value),
    pdu: decodePdu(pduTlv),
  };
}

/** Decode an SNMP PDU and its variable-binding list. */
export function decodePdu(pdu: BerTlv): DecodedPdu {
  if ((pdu.tag & 0xe0) !== 0xa0) throw new TypeError(`Unexpected SNMP PDU tag: 0x${pdu.tag.toString(16)}`);
  const fields = readChildren(pdu.value);
  if (fields.length !== 4) throw new TypeError("SNMP PDU must contain four fields");
  const requestId = safeNumber(decodeIntegerTlv(fields[0]!, "request id"), "request id");
  const firstField = safeNumber(decodeIntegerTlv(fields[1]!, "PDU field"), "PDU field");
  const secondField = safeNumber(decodeIntegerTlv(fields[2]!, "PDU field"), "PDU field");
  expectTag(fields[3]!, 0x30, "VarBind list");

  const bindings = readChildren(fields[3]!.value).map(decodeVarBind);
  return { tag: pdu.tag, requestId, firstField, secondField, bindings };
}

/** Decode one VarBind item into the public typed binding union. */
export function decodeVarBind(item: BerTlv): VarBind {
  expectTag(item, 0x30, "VarBind");
  const fields = readChildren(item.value);
  if (fields.length !== 2) throw new TypeError("VarBind must contain an OID and a value");
  expectTag(fields[0]!, 0x06, "VarBind OID");
  const oid = decodeOidValue(fields[0]!.value);
  const value = fields[1]!;

  switch (value.tag) {
    case 0x02:
      return { oid, type: "INTEGER", value: safeNumber(decodeIntegerValue(value.value), "INTEGER") };
    case 0x04:
      return { oid, type: "OCTET_STRING", value: value.value.slice() };
    case 0x06:
      return { oid, type: "OBJECT_IDENTIFIER", value: decodeOidValue(value.value) };
    case 0x05:
      ensureEmpty(value, "NULL");
      return { oid, type: "NULL", value: null };
    case 0x40:
      if (value.value.length !== 4) throw new TypeError("IpAddress must contain four bytes");
      return { oid, type: "IP_ADDRESS", value: [...value.value].join(".") };
    case 0x41:
      return { oid, type: "COUNTER32", value: safeUnsignedNumber(value.value, "Counter32") };
    case 0x42:
      return { oid, type: "GAUGE32", value: safeUnsignedNumber(value.value, "Gauge32") };
    case 0x43:
      return { oid, type: "TIME_TICKS", value: safeUnsignedNumber(value.value, "TimeTicks") };
    case 0x44:
      return { oid, type: "OPAQUE", value: value.value.slice() };
    case 0x46: {
      const counter = decodeUnsignedValue(value.value);
      if (counter > 0xffff_ffff_ffff_ffffn) throw new RangeError("Counter64 exceeds its unsigned 64-bit range");
      return { oid, type: "COUNTER64", value: counter };
    }
    case 0x80:
      return decodeException(oid, value, "NO_SUCH_OBJECT");
    case 0x81:
      return decodeException(oid, value, "NO_SUCH_INSTANCE");
    case 0x82:
      return decodeException(oid, value, "END_OF_MIB_VIEW");
    default:
      throw new TypeError(`Unsupported SNMP value tag: 0x${value.tag.toString(16)}`);
  }
}

/** Decode a BER OBJECT IDENTIFIER value to dotted decimal. */
export function decodeOidValue(bytes: Uint8Array): Oid {
  if (bytes.length === 0) throw new TypeError("OBJECT IDENTIFIER cannot be empty");
  const subidentifiers: bigint[] = [];
  let current = 0n;
  let continuation = false;

  for (const byte of bytes) {
    current = (current << 7n) | BigInt(byte & 0x7f);
    continuation = (byte & 0x80) !== 0;
    if (!continuation) {
      subidentifiers.push(current);
      current = 0n;
    }
  }
  if (continuation) throw new TypeError("Truncated base-128 OID arc");
  if (subidentifiers.length === 0) throw new TypeError("OBJECT IDENTIFIER has no subidentifiers");

  const first = subidentifiers.shift()!;
  const firstArc = first < 40n ? 0n : first < 80n ? 1n : 2n;
  const secondArc = first - firstArc * 40n;
  return [firstArc, secondArc, ...subidentifiers].map(String).join(".");
}

/** Ensure a TLV has the expected tag and provide a field-specific error. */
export function expectTag(item: BerTlv, expected: number, field: string): void {
  if (item.tag !== expected) {
    throw new TypeError(`${field} has BER tag 0x${item.tag.toString(16)}, expected 0x${expected.toString(16)}`);
  }
}

/** Parse all immediate BER child items and reject leftover bytes. */
export function readChildren(bytes: Uint8Array): BerTlv[] {
  const children: BerTlv[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const child = readTlv(bytes, offset);
    children.push(child);
    offset = child.nextOffset;
  }
  return children;
}

/** Decode an INTEGER TLV and verify its tag. */
function decodeIntegerTlv(item: BerTlv, field: string): bigint {
  expectTag(item, 0x02, field);
  return decodeIntegerValue(item.value);
}

/** Convert a BigInt to a safe JavaScript number. */
function safeNumber(value: bigint, field: string): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new RangeError(`${field} exceeds JavaScript's safe integer range`);
  return number;
}

/** Convert an unsigned BER value to a safe JavaScript number. */
function safeUnsignedNumber(bytes: Uint8Array, field: string): number {
  const value = decodeUnsignedValue(bytes);
  if (value > 0xffff_ffffn) throw new RangeError(`${field} exceeds its unsigned 32-bit range`);
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new RangeError(`${field} exceeds JavaScript's safe integer range`);
  return number;
}

/** Convert an exception syntax TLV into a null-valued typed binding. */
function decodeException(oid: Oid, value: BerTlv, type: SnmpValueType): VarBind {
  ensureEmpty(value, type);
  if (type !== "NO_SUCH_OBJECT" && type !== "NO_SUCH_INSTANCE" && type !== "END_OF_MIB_VIEW") {
    throw new TypeError(`Invalid SNMP exception syntax: ${type}`);
  }
  return { oid, type, value: null };
}

/** Validate that a NULL-like value contains no bytes. */
function ensureEmpty(item: BerTlv, field: string): void {
  if (item.value.length !== 0) throw new TypeError(`${field} value must be empty`);
}

/** Verify a top-level BER item consumes the entire message. */
function assertConsumed(bytes: Uint8Array, nextOffset: number): void {
  if (nextOffset !== bytes.length) throw new TypeError("Trailing bytes after BER message");
}
