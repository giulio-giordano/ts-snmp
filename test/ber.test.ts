import { expect, test } from "bun:test";
import { decodeCommunityMessage, decodeIntegerValue, decodeOidValue, decodeVarBind, readTlv } from "../src/ber/decoder.ts";
import { encodeCommunityMessage, encodeInteger, encodeOid, encodePdu, encodeVarBind } from "../src/ber/encoder.ts";
import { decodeV3Message, encodeScopedPdu, encodeV3Message } from "../src/protocol/v3.ts";
import type { VarBind } from "../src/types.ts";

/** Verify every supported SMI binding syntax survives BER encoding and decoding. */
test("BER codec round-trips every supported VarBind type", () => {
  const bindings: VarBind[] = [
    { oid: "1.3.6.1.1", type: "INTEGER", value: -123 },
    { oid: "1.3.6.1.2", type: "OCTET_STRING", value: Uint8Array.of(0, 0xff, 0x41) },
    { oid: "1.3.6.1.3", type: "OBJECT_IDENTIFIER", value: "1.3.6.1.4.1.99999" },
    { oid: "1.3.6.1.4", type: "NULL", value: null },
    { oid: "1.3.6.1.5", type: "IP_ADDRESS", value: "192.0.2.7" },
    { oid: "1.3.6.1.6", type: "COUNTER32", value: 4_294_967_295 },
    { oid: "1.3.6.1.7", type: "GAUGE32", value: 4_294_967_295 },
    { oid: "1.3.6.1.8", type: "TIME_TICKS", value: 4_294_967_295 },
    { oid: "1.3.6.1.9", type: "OPAQUE", value: Uint8Array.of(0xde, 0xad) },
    { oid: "1.3.6.1.10", type: "COUNTER64", value: 18_446_744_073_709_551_615n },
    { oid: "1.3.6.1.11", type: "NO_SUCH_OBJECT", value: null },
    { oid: "1.3.6.1.12", type: "NO_SUCH_INSTANCE", value: null },
    { oid: "1.3.6.1.13", type: "END_OF_MIB_VIEW", value: null },
  ];

  for (const binding of bindings) {
    expect(decodeVarBind(readTlv(encodeVarBind(binding)))).toEqual(binding);
  }
});

/** Verify BER OID base-128 handling for large arcs and optional leading dots. */
test("OID codec handles leading dots and large arcs", () => {
  const encoded = encodeOid(".2.999.3.0");
  const tlv = readTlv(encoded);
  expect(decodeOidValue(tlv.value)).toBe("2.999.3.0");
});

/** Verify signed INTEGER minimal encoding remains correctly decodable. */
test("BER signed INTEGER preserves negative values", () => {
  for (const value of [-32_769, -129, -128, -1, 0, 127, 128, 32_768]) {
    expect(decodeIntegerValue(readTlv(encodeInteger(value)).value)).toBe(BigInt(value));
  }
});

/** Verify v1 and v2c message wrappers preserve versions, communities, and PDUs. */
test("community message codec handles SNMPv1 and SNMPv2c", () => {
  const response = encodePdu(0xa2, 91, 0, 0, [
    { oid: "1.3.6.1.2.1.1.1.0", type: "OCTET_STRING", value: new TextEncoder().encode("agent") },
  ]);
  for (const version of [0, 1] as const) {
    const decoded = decodeCommunityMessage(encodeCommunityMessage(version, "public", response));
    expect(decoded.version).toBe(version);
    expect(decoded.community).toBe("public");
    expect(decoded.pdu.requestId).toBe(91);
  }
});

/** Verify the SNMPv3 envelope and plaintext ScopedPDU layout. */
test("SNMPv3 envelope encodes and decodes a plaintext scoped PDU", () => {
  const engineId = Uint8Array.of(0x80, 0, 0, 1, 2, 3);
  const pdu = encodePdu(0xa2, 25, 0, 0, []);
  const scoped = encodeScopedPdu(engineId, "", pdu);
  const message = encodeV3Message(
    { messageId: 25, maxSize: 65_507, flags: 0, securityModel: 3 },
    {
      engineId,
      engineBoots: 1,
      engineTime: 2,
      username: "user",
      authParameters: new Uint8Array(),
      privacyParameters: new Uint8Array(),
    },
    scoped,
  );
  const decoded = decodeV3Message(message);
  expect(decoded.header.messageId).toBe(25);
  expect(decoded.scopedPdu?.pdu.requestId).toBe(25);
  expect(decoded.security.username).toBe("user");
});
