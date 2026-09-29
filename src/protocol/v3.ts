import {
  decodeIntegerValue,
  decodePdu,
  expectTag,
  readChildren,
  readTlv,
  type DecodedPdu,
} from "../ber/decoder.ts";
import {
  encodeInteger,
  encodeOctetString,
  encodeSequence,
  encodeTlv,
} from "../ber/encoder.ts";

/** Parsed USM security parameters carried in an SNMPv3 message. */
export interface UsmParameters {
  /** Authoritative engine ID; empty during engine discovery. */
  engineId: Uint8Array;
  /** Authoritative engine boots counter. */
  engineBoots: number;
  /** Authoritative engine time in seconds. */
  engineTime: number;
  /** USM security name. */
  username: string;
  /** Message authentication digest, empty for noAuthNoPriv. */
  authParameters: Uint8Array;
  /** DES privacy salt, empty when privacy is not used. */
  privacyParameters: Uint8Array;
}

/** SNMPv3 message header fields. */
export interface V3Header {
  /** Message identifier distinct from the scoped PDU request identifier. */
  messageId: number;
  /** Maximum message size supported by the sender. */
  maxSize: number;
  /** msgFlags octet; auth=0x01, privacy=0x02, reportable=0x04. */
  flags: number;
  /** Security model; USM is model 3. */
  securityModel: number;
}

/** Decoded plaintext ScopedPDU fields. */
export interface V3ScopedPdu {
  /** Context engine ID identifying the management context. */
  contextEngineId: Uint8Array;
  /** Context name identifying a management context within the engine. */
  contextName: string;
  /** Scoped PDU contents. */
  pdu: DecodedPdu;
}

/** Decoded SNMPv3 message envelope. */
export interface V3Message {
  /** Decoded message header. */
  header: V3Header;
  /** Decoded USM security parameters. */
  security: UsmParameters;
  /** Plaintext scoped PDU, absent when the data field is encrypted. */
  scopedPdu?: V3ScopedPdu;
  /** Encrypted scoped-PDU bytes, absent when plaintext. */
  encryptedPdu?: Uint8Array;
}

/** Encode USM parameters into the OCTET STRING payload required by SNMPv3. */
export function encodeUsmParameters(parameters: UsmParameters): Uint8Array {
  const encodedUsm = encodeSequence(
    encodeOctetString(parameters.engineId),
    encodeInteger(parameters.engineBoots),
    encodeInteger(parameters.engineTime),
    encodeOctetString(parameters.username),
    encodeOctetString(parameters.authParameters),
    encodeOctetString(parameters.privacyParameters),
  );
  return encodeOctetString(encodedUsm);
}

/** Encode a scoped PDU containing context identity and an encoded PDU. */
export function encodeScopedPdu(
  contextEngineId: Uint8Array,
  contextName: string,
  pdu: Uint8Array,
): Uint8Array {
  return encodeSequence(encodeOctetString(contextEngineId), encodeOctetString(contextName), pdu);
}

/** Encode an SNMPv3 envelope from its header, USM parameters, and scoped data. */
export function encodeV3Message(
  header: V3Header,
  security: UsmParameters,
  scopedData: Uint8Array,
): Uint8Array {
  const encodedHeader = encodeSequence(
    encodeInteger(header.messageId),
    encodeInteger(header.maxSize),
    encodeOctetString(Uint8Array.of(header.flags)),
    encodeInteger(header.securityModel),
  );
  return encodeSequence(
    encodeInteger(3),
    encodedHeader,
    encodeUsmParameters(security),
    scopedData,
  );
}

/** Decode an SNMPv3 envelope, leaving authentication and decryption to USM. */
export function decodeV3Message(packet: Uint8Array): V3Message {
  const outer = readTlv(packet);
  expectTag(outer, 0x30, "SNMPv3 message");
  if (outer.nextOffset !== packet.length) throw new TypeError("Trailing bytes after SNMPv3 message");
  const fields = readChildren(outer.value);
  if (fields.length !== 4) throw new TypeError("SNMPv3 message must contain four fields");
  expectTag(fields[0]!, 0x02, "SNMP message version");
  if (decodeIntegerValue(fields[0]!.value) !== 3n) throw new TypeError("Message is not SNMPv3");

  expectTag(fields[1]!, 0x30, "SNMPv3 headerData");
  const headerFields = readChildren(fields[1]!.value);
  if (headerFields.length !== 4) throw new TypeError("SNMPv3 headerData must contain four fields");
  const flagsTlv = headerFields[2]!;
  expectTag(flagsTlv, 0x04, "SNMPv3 msgFlags");
  if (flagsTlv.value.length !== 1) throw new TypeError("SNMPv3 msgFlags must be one octet");

  expectTag(headerFields[0]!, 0x02, "message ID");
  expectTag(headerFields[1]!, 0x02, "maximum message size");
  expectTag(headerFields[3]!, 0x02, "security model");
  const header: V3Header = {
    messageId: safeInteger(headerFields[0]!.value, "message ID"),
    maxSize: safeInteger(headerFields[1]!.value, "maximum message size"),
    flags: flagsTlv.value[0]!,
    securityModel: safeInteger(headerFields[3]!.value, "security model"),
  };

  expectTag(fields[2]!, 0x04, "SNMPv3 securityParameters");
  const security = decodeUsmParameters(fields[2]!.value);
  const data = fields[3]!;
  if (data.tag === 0x04) {
    return { header, security, encryptedPdu: data.value.slice() };
  }
  expectTag(data, 0x30, "SNMPv3 scopedPDU");
  const scopedFields = readChildren(data.value);
  if (scopedFields.length !== 3) throw new TypeError("SNMPv3 scopedPDU must contain three fields");
  expectTag(scopedFields[0]!, 0x04, "contextEngineID");
  expectTag(scopedFields[1]!, 0x04, "contextName");
  return {
    header,
    security,
    scopedPdu: {
      contextEngineId: scopedFields[0]!.value.slice(),
      contextName: new TextDecoder().decode(scopedFields[1]!.value),
      pdu: decodePdu(scopedFields[2]!),
    },
  };
}

/** Decode the sequence nested inside the SNMPv3 securityParameters OCTET STRING. */
function decodeUsmParameters(bytes: Uint8Array): UsmParameters {
  const sequence = readTlv(bytes);
  expectTag(sequence, 0x30, "USM security parameters");
  if (sequence.nextOffset !== bytes.length) throw new TypeError("Trailing bytes in USM security parameters");
  const fields = readChildren(sequence.value);
  if (fields.length !== 6) throw new TypeError("USM parameters must contain six fields");
  expectTag(fields[0]!, 0x04, "authoritative engine ID");
  expectTag(fields[3]!, 0x04, "USM username");
  expectTag(fields[4]!, 0x04, "USM authentication parameters");
  expectTag(fields[5]!, 0x04, "USM privacy parameters");
  expectTag(fields[1]!, 0x02, "engine boots");
  expectTag(fields[2]!, 0x02, "engine time");
  return {
    engineId: fields[0]!.value.slice(),
    engineBoots: safeInteger(fields[1]!.value, "engine boots"),
    engineTime: safeInteger(fields[2]!.value, "engine time"),
    username: new TextDecoder().decode(fields[3]!.value),
    authParameters: fields[4]!.value.slice(),
    privacyParameters: fields[5]!.value.slice(),
  };
}

/** Decode and validate a non-negative SNMPv3 header/USM integer. */
function safeInteger(bytes: Uint8Array, field: string): number {
  const value = decodeIntegerValue(bytes);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new RangeError(`Invalid ${field}`);
  return number;
}
