import type { Oid, VarBind } from "../types.ts";

/** Encode one BER tag-length-value item. */
export function encodeTlv(tag: number, value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  const result = new Uint8Array(1 + length.length + value.length);
  result[0] = tag;
  result.set(length, 1);
  result.set(value, 1 + length.length);
  return result;
}

/** Encode a BER SEQUENCE containing already encoded children. */
export function encodeSequence(...children: Uint8Array[]): Uint8Array {
  return encodeTlv(0x30, concatenate(children));
}

/** Encode a signed BER INTEGER using the shortest valid two's-complement form. */
export function encodeInteger(value: number | bigint): Uint8Array {
  let remaining = BigInt(value);
  const bytes: number[] = [];
  let done = false;

  while (!done) {
    const byte = Number(remaining & 0xffn);
    bytes.unshift(byte);
    remaining >>= 8n;
    const signBitSet = (byte & 0x80) !== 0;
    done = (remaining === 0n && !signBitSet) || (remaining === -1n && signBitSet);
  }

  return encodeTlv(0x02, Uint8Array.from(bytes));
}

/** Encode a non-negative BER INTEGER for application counter values. */
export function encodeUnsignedInteger(tag: number, value: number | bigint): Uint8Array {
  let remaining = BigInt(value);
  if (remaining < 0n) throw new RangeError("Unsigned BER integer cannot be negative");
  const maximum = tag === 0x46 ? 0xffff_ffff_ffff_ffffn : 0xffff_ffffn;
  if (remaining > maximum) throw new RangeError(`SNMP unsigned value exceeds the range for tag 0x${tag.toString(16)}`);

  const bytes: number[] = [];
  do {
    bytes.unshift(Number(remaining & 0xffn));
    remaining >>= 8n;
  } while (remaining > 0n);

  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return encodeTlv(tag, Uint8Array.from(bytes));
}

/** Encode a BER OCTET STRING. */
export function encodeOctetString(value: Uint8Array | string, tag = 0x04): Uint8Array {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  return encodeTlv(tag, bytes);
}

/** Encode BER NULL. */
export function encodeNull(tag = 0x05): Uint8Array {
  return encodeTlv(tag, new Uint8Array());
}

/** Encode a dotted-decimal OID into BER base-128 subidentifiers. */
export function encodeOid(oid: Oid): Uint8Array {
  const arcs = parseOid(oid);
  if (arcs.length < 2) throw new TypeError(`OID must contain at least two arcs: ${oid}`);
  if (arcs[0]! > 2n) throw new TypeError(`OID first arc must be 0, 1, or 2: ${oid}`);
  if (arcs[0]! < 2n && arcs[1]! > 39n) {
    throw new TypeError(`OID second arc must be less than 40 when first arc is 0 or 1: ${oid}`);
  }

  const encoded: number[] = [];
  appendBase128(encoded, arcs[0]! * 40n + arcs[1]!);
  for (const arc of arcs.slice(2)) appendBase128(encoded, arc);
  return encodeTlv(0x06, Uint8Array.from(encoded));
}

/** Encode an SNMP VarBind using the syntax tag and typed value. */
export function encodeVarBind(binding: VarBind): Uint8Array {
  const oid = encodeOid(binding.oid);
  let value: Uint8Array;

  switch (binding.type) {
    case "INTEGER":
      value = encodeInteger(binding.value);
      break;
    case "OCTET_STRING":
      value = encodeOctetString(binding.value);
      break;
    case "OBJECT_IDENTIFIER":
      value = encodeOid(binding.value);
      break;
    case "NULL":
      value = encodeNull();
      break;
    case "IP_ADDRESS":
      value = encodeTlv(0x40, parseIpv4(binding.value));
      break;
    case "COUNTER32":
      value = encodeUnsignedInteger(0x41, binding.value);
      break;
    case "GAUGE32":
      value = encodeUnsignedInteger(0x42, binding.value);
      break;
    case "TIME_TICKS":
      value = encodeUnsignedInteger(0x43, binding.value);
      break;
    case "OPAQUE":
      value = encodeOctetString(binding.value, 0x44);
      break;
    case "COUNTER64":
      value = encodeUnsignedInteger(0x46, binding.value);
      break;
    case "NO_SUCH_OBJECT":
      value = encodeNull(0x80);
      break;
    case "NO_SUCH_INSTANCE":
      value = encodeNull(0x81);
      break;
    case "END_OF_MIB_VIEW":
      value = encodeNull(0x82);
      break;
  }

  return encodeSequence(oid, value);
}

/** Encode the VarBind list body as a BER SEQUENCE. */
export function encodeVarBindList(bindings: VarBind[]): Uint8Array {
  return encodeSequence(...bindings.map(encodeVarBind));
}

/** Encode an SNMP request or response PDU body. */
export function encodePdu(
  tag: number,
  requestId: number,
  firstField: number,
  secondField: number,
  bindings: VarBind[],
): Uint8Array {
  const body = concatenate([
    encodeInteger(requestId),
    encodeInteger(firstField),
    encodeInteger(secondField),
    encodeVarBindList(bindings),
  ]);
  return encodeTlv(tag, body);
}

/** Encode the common SNMPv1/v2c message wrapper. */
export function encodeCommunityMessage(version: 0 | 1, community: string, pdu: Uint8Array): Uint8Array {
  return encodeSequence(encodeInteger(version), encodeOctetString(community), pdu);
}

/** Concatenate byte arrays without changing the source arrays. */
export function concatenate(chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

/** Encode a BER definite-form length. */
function encodeLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

/** Parse and validate dotted-decimal OID arcs. */
function parseOid(oid: string): bigint[] {
  const parts = oid.split(".");
  if (parts[0] === "") parts.shift();
  if (parts.length < 2 || parts.some((part) => !/^\d+$/.test(part))) {
    throw new TypeError(`Invalid dotted-decimal OID: ${oid}`);
  }
  return parts.map((part) => BigInt(part));
}

/** Append one non-negative base-128 encoded OID subidentifier. */
function appendBase128(target: number[], value: bigint): void {
  if (value < 0n) throw new TypeError("OID arcs cannot be negative");
  const bytes = [Number(value & 0x7fn)];
  value >>= 7n;
  while (value > 0n) {
    bytes.unshift(Number(value & 0x7fn) | 0x80);
    value >>= 7n;
  }
  target.push(...bytes);
}

/** Convert dotted IPv4 text to the four-byte IpAddress application value. */
function parseIpv4(address: string): Uint8Array {
  const parts = address.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    throw new TypeError(`Invalid IPv4 address: ${address}`);
  }
  return Uint8Array.from(parts.map(Number));
}
