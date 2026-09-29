import { decodeCommunityResponse, encodeCommunityRequest, isMatchingCommunityResponse } from "./community.ts";
import { encodeGetBulkPdu, encodeGetNextPdu, encodeGetPdu } from "./pdu.ts";
import type { DecodedPdu } from "../ber/decoder.ts";
import type { Oid } from "../types.ts";

/** Encode an SNMPv2c GetRequest message. */
export function encodeV2cGet(community: string, requestId: number, oid: Oid): Uint8Array {
  return encodeCommunityRequest(1, community, encodeGetPdu(requestId, [oid]));
}

/** Encode an SNMPv2c GetNextRequest message used for non-bulk traversal. */
export function encodeV2cGetNext(community: string, requestId: number, oid: Oid): Uint8Array {
  return encodeCommunityRequest(1, community, encodeGetNextPdu(requestId, oid));
}

/** Encode an SNMPv2c GetBulkRequest message used by walk. */
export function encodeV2cGetBulk(
  community: string,
  requestId: number,
  oid: Oid,
  maxRepetitions: number,
): Uint8Array {
  return encodeCommunityRequest(1, community, encodeGetBulkPdu(requestId, oid, maxRepetitions));
}

/** Decode and validate an SNMPv2c response message. */
export function decodeV2cResponse(packet: Uint8Array, community: string, requestId: number): DecodedPdu {
  return decodeCommunityResponse(packet, 1, community, requestId);
}

/** Identify a response matching an outstanding SNMPv2c request. */
export function isV2cResponse(packet: Uint8Array, community: string, requestId: number): boolean {
  return isMatchingCommunityResponse(packet, 1, community, requestId);
}
