import { encodeNull, encodePdu } from "../ber/encoder.ts";
import type { Oid, VarBind } from "../types.ts";

/** Context-specific PDU tags defined by the SNMP protocol. */
export const PDU_TAG = {
  /** GetRequest-PDU. */
  get: 0xa0,
  /** GetNextRequest-PDU. */
  getNext: 0xa1,
  /** Response-PDU. */
  response: 0xa2,
  /** SetRequest-PDU (not currently exposed by the client interface). */
  set: 0xa3,
  /** GetBulkRequest-PDU. */
  getBulk: 0xa5,
} as const;

/** Encode a GetRequest PDU with one NULL placeholder per requested OID. */
export function encodeGetPdu(requestId: number, oids: Oid[]): Uint8Array {
  return encodePdu(PDU_TAG.get, requestId, 0, 0, nullBindings(oids));
}

/** Encode a GetNextRequest PDU for a single cursor OID. */
export function encodeGetNextPdu(requestId: number, oid: Oid): Uint8Array {
  return encodePdu(PDU_TAG.getNext, requestId, 0, 0, nullBindings([oid]));
}

/** Encode a GetBulkRequest PDU for subtree traversal. */
export function encodeGetBulkPdu(requestId: number, oid: Oid, maxRepetitions: number): Uint8Array {
  return encodePdu(PDU_TAG.getBulk, requestId, 0, maxRepetitions, nullBindings([oid]));
}

/** Build the placeholder bindings carried in SNMP read requests. */
function nullBindings(oids: Oid[]): VarBind[] {
  return oids.map((oid) => ({ oid, type: "NULL", value: null }));
}

/** Encode a zero-payload SNMP NULL value for protocol helpers. */
export function encodeNullValue(): Uint8Array {
  return encodeNull();
}
