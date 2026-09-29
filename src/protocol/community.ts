import { decodeCommunityMessage, type DecodedPdu } from "../ber/decoder.ts";
import { encodeCommunityMessage } from "../ber/encoder.ts";
import { SnmpError } from "../types.ts";

/** Encode a community-based SNMP request with a complete PDU. */
export function encodeCommunityRequest(
  wireVersion: 0 | 1,
  community: string,
  pdu: Uint8Array,
): Uint8Array {
  return encodeCommunityMessage(wireVersion, community, pdu);
}

/** Decode and validate a community-based response before returning its PDU. */
export function decodeCommunityResponse(
  packet: Uint8Array,
  expectedVersion: 0 | 1,
  expectedCommunity: string,
  expectedRequestId: number,
): DecodedPdu {
  const message = decodeCommunityMessage(packet);
  if (message.version !== expectedVersion) throw new SnmpError("SNMP response version did not match request", "SNMP_VERSION_MISMATCH");
  if (message.community !== expectedCommunity) throw new SnmpError("SNMP response community did not match request", "SNMP_COMMUNITY_MISMATCH");
  if (message.pdu.tag !== 0xa2) throw new SnmpError("SNMP agent returned a non-response PDU", "SNMP_PDU_MISMATCH");
  if (message.pdu.requestId !== expectedRequestId) throw new SnmpError("SNMP response request ID did not match request", "SNMP_REQUEST_ID_MISMATCH");
  return message.pdu;
}

/** Check whether a datagram is a matching community-based response. */
export function isMatchingCommunityResponse(
  packet: Uint8Array,
  expectedVersion: 0 | 1,
  expectedCommunity: string,
  expectedRequestId: number,
): boolean {
  try {
    decodeCommunityResponse(packet, expectedVersion, expectedCommunity, expectedRequestId);
    return true;
  } catch {
    return false;
  }
}
