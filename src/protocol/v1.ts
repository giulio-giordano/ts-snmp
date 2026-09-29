import { decodeCommunityResponse, encodeCommunityRequest, isMatchingCommunityResponse } from "./community.ts";
import { encodeGetNextPdu, encodeGetPdu } from "./pdu.ts";
import type { DecodedPdu } from "../ber/decoder.ts";
import type { Oid } from "../types.ts";

/** Encode an SNMPv1 GetRequest message. */
export function encodeV1Get(community: string, requestId: number, oid: Oid): Uint8Array {
  return encodeCommunityRequest(0, community, encodeGetPdu(requestId, [oid]));
}

/** Encode an SNMPv1 GetNextRequest message used by walk. */
export function encodeV1GetNext(community: string, requestId: number, oid: Oid): Uint8Array {
  return encodeCommunityRequest(0, community, encodeGetNextPdu(requestId, oid));
}

/** Decode and validate an SNMPv1 response message. */
export function decodeV1Response(packet: Uint8Array, community: string, requestId: number): DecodedPdu {
  return decodeCommunityResponse(packet, 0, community, requestId);
}

/** Identify a response matching an outstanding SNMPv1 request. */
export function isV1Response(packet: Uint8Array, community: string, requestId: number): boolean {
  return isMatchingCommunityResponse(packet, 0, community, requestId);
}
