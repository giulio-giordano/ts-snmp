import { encodeGetBulkPdu, encodeGetPdu } from "../protocol/pdu.ts";
import { decodeV1Response, encodeV1Get, encodeV1GetNext, isV1Response } from "../protocol/v1.ts";
import {
  decodeV2cResponse,
  encodeV2cGet,
  encodeV2cGetBulk,
  encodeV2cGetNext,
  isV2cResponse,
} from "../protocol/v2c.ts";
import { decodeV3Message, encodeScopedPdu, encodeV3Message, type UsmParameters, type V3Message } from "../protocol/v3.ts";
import {
  authenticateV3Message,
  createDesSalt,
  createInitialDesSaltCounter,
  decryptScopedPdu,
  encryptScopedPdu,
  passwordToLocalizedKey,
  verifyV3Message,
} from "../protocol/usm.ts";
import { DefaultUdpTransport, UdpTransport } from "../transport/UdpTransport.ts";
import { decodePdu, expectTag, readTlv, type DecodedPdu } from "../ber/decoder.ts";
import { encodeOctetString, encodeOid } from "../ber/encoder.ts";
import {
  SnmpError,
  SnmpResponseError,
  type Oid,
  type Snmp,
  type SnmpOptions,
  type VarBind,
} from "../types.ts";

/** Default number of rows requested per SNMPv2/v3 GetBulk round trip. */
const DEFAULT_MAX_REPETITIONS = 10;
/** Maximum SNMP message size advertised by this client. */
const MAX_MESSAGE_SIZE = 65_507;

/**
 * UDP-backed SNMPv1, SNMPv2c, and SNMPv3 client implementing get and walk.
 * Protocol serialization and transport are delegated to dedicated modules.
 */
export class SnmpClient implements Snmp {
  private readonly transport: UdpTransport;
  private requestId = 0;
  private messageId = 0;
  private privacySaltCounter = createInitialDesSaltCounter();
  private engine?: EngineCache;
  private engineDiscovery?: Promise<EngineCache>;

  /** Construct the client and its UDP transport from versioned options. */
  constructor(private readonly options: SnmpOptions, transport?: UdpTransport) {
    validateOptions(options);
    this.transport = transport ?? new DefaultUdpTransport({
      host: options.host,
      port: options.port ?? 161,
      timeoutMs: options.timeoutMs ?? 1_000,
      retries: options.retries ?? 1,
    });
  }

  /** Read one OID and return its typed value binding. */
  async get(oid: Oid): Promise<VarBind> {
    encodeOid(oid);
    const requestId = this.nextRequestId();
    const response = await this.requestGet(oid, requestId);
    this.assertSuccessfulResponse(response);
    if (response.bindings.length !== 1) {
      throw new SnmpError(`Expected one VarBind for ${oid}, received ${response.bindings.length}`, "SNMP_BINDING_COUNT_MISMATCH");
    }
    const binding = response.bindings[0]!;
    if (normalizeOid(binding.oid) !== normalizeOid(oid)) {
      throw new SnmpError(`SNMP agent returned ${binding.oid} for requested OID ${oid}`, "SNMP_OID_MISMATCH");
    }
    return binding;
  }

  /** Walk an OID subtree, yielding each typed binding as it is received. */
  async *walk(rootOid: Oid): AsyncIterable<VarBind> {
    encodeOid(rootOid);
    const root = normalizeOid(rootOid);
    let cursor = root;

    while (true) {
      const requestId = this.nextRequestId();
      const response = await this.requestWalkBatch(cursor, requestId);
      if (!response) return;
      if (response.firstField !== 0) {
        if (this.options.version === "v1" && response.firstField === 2) return;
        throw createResponseError(response);
      }
      if (response.bindings.length === 0) return;

      for (const binding of response.bindings) {
        if (isEndOfWalk(binding)) return;
        if (!isWithinSubtree(root, binding.oid)) return;
        if (compareOids(binding.oid, cursor) <= 0) {
          throw new SnmpError(`SNMP walk did not advance past ${cursor}`, "SNMP_WALK_NO_PROGRESS");
        }
        cursor = normalizeOid(binding.oid);
        yield binding;
      }
    }
  }

  /** Close the owned UDP socket. */
  async close(): Promise<void> {
    await this.transport.close();
  }

  /** Send and decode a version-specific GetRequest. */
  private async requestGet(oid: Oid, requestId: number): Promise<DecodedPdu> {
    switch (this.options.version) {
      case "v1": {
        const community = this.options.community;
        const packet = encodeV1Get(community, requestId, oid);
        const response = await this.transport.exchange(
          packet,
          (data) => isV1Response(data, community, requestId),
        );
        return decodeV1Response(response, community, requestId);
      }
      case "v2c": {
        const community = this.options.community;
        const packet = encodeV2cGet(community, requestId, oid);
        const response = await this.transport.exchange(
          packet,
          (data) => isV2cResponse(data, community, requestId),
        );
        return decodeV2cResponse(response, community, requestId);
      }
      case "v3":
        return this.requestV3(encodeGetPdu(requestId, [oid]), requestId);
    }
  }

  /** Send and decode the next version-specific walk batch. */
  private async requestWalkBatch(oid: Oid, requestId: number): Promise<DecodedPdu | undefined> {
    switch (this.options.version) {
      case "v1": {
        const community = this.options.community;
        const packet = encodeV1GetNext(community, requestId, oid);
        const response = await this.transport.exchange(
          packet,
          (data) => isV1Response(data, community, requestId),
        );
        return decodeV1Response(response, community, requestId);
      }
      case "v2c": {
        const community = this.options.community;
        const packet = encodeV2cGetBulk(community, requestId, oid, DEFAULT_MAX_REPETITIONS);
        const response = await this.transport.exchange(
          packet,
          (data) => isV2cResponse(data, community, requestId),
        );
        return decodeV2cResponse(response, community, requestId);
      }
      case "v3":
        return this.requestV3(encodeGetBulkPdu(requestId, oid, DEFAULT_MAX_REPETITIONS), requestId);
    }
  }

  /** Execute one SNMPv3 request with engine discovery, USM auth, and optional DES. */
  private async requestV3(pdu: Uint8Array, requestId: number): Promise<DecodedPdu> {
    const options = this.options;
    if (options.version !== "v3") throw new SnmpError("SNMPv3 options are required", "SNMPV3_OPTIONS_REQUIRED");
    const engine = await this.getAuthoritativeEngine();
    const security = options.security;
    const authKey = security.securityLevel === "noAuthNoPriv"
      ? undefined
      : passwordToLocalizedKey(security.authPassword, engine.engineId);
    const privacyKey = security.securityLevel === "authPriv"
      ? passwordToLocalizedKey(security.privacyPassword, engine.engineId)
      : undefined;
    let salt: Uint8Array<ArrayBufferLike> = new Uint8Array();
    if (privacyKey) {
      if (this.privacySaltCounter >= 0xffff_ffff) {
        throw new SnmpError("SNMPv3 DES privacy salt counter is exhausted", "SNMPV3_PRIVACY_SALT_EXHAUSTED");
      }
      salt = createDesSalt(engine.engineBoots, this.privacySaltCounter++);
    }
    const securityParameters: UsmParameters = {
      engineId: engine.engineId,
      engineBoots: engine.engineBoots,
      engineTime: currentEngineTime(engine),
      username: security.username,
      authParameters: authKey ? new Uint8Array(12) : new Uint8Array(),
      privacyParameters: salt,
    };
    const contextEngineId = engine.engineId;
    const scopedPdu = encodeScopedPdu(contextEngineId, options.contextName ?? "", pdu);
    const encryptedScopedPdu = privacyKey ? encryptScopedPdu(scopedPdu, privacyKey, salt) : undefined;
    const messageId = this.nextMessageId();
    const flags = 0x04 | (authKey ? 0x01 : 0) | (privacyKey ? 0x02 : 0);
    let packet = encodeV3Message(
      { messageId, maxSize: MAX_MESSAGE_SIZE, flags, securityModel: 3 },
      securityParameters,
      encryptedScopedPdu ? encodeOctetString(encryptedScopedPdu) : scopedPdu,
    );
    if (authKey) packet = authenticateV3Message(packet, authKey);

    const responsePacket = await this.transport.exchange(packet, (data) => isV3Response(data, messageId));
    const response = decodeV3Message(responsePacket);
    if (response.header.securityModel !== 3) {
      throw new SnmpError("SNMPv3 response did not use the USM security model", "SNMPV3_SECURITY_MODEL_MISMATCH");
    }
    const expectedAuth = authKey !== undefined;
    const expectedPrivacy = privacyKey !== undefined;
    if (((response.header.flags & 0x01) !== 0) !== expectedAuth || ((response.header.flags & 0x02) !== 0) !== expectedPrivacy) {
      throw new SnmpError("SNMPv3 response security level did not match the request", "SNMPV3_SECURITY_LEVEL_MISMATCH");
    }
    if (!equalBytes(response.security.engineId, engine.engineId)) {
      throw new SnmpError("SNMPv3 response authoritative engine ID changed", "SNMPV3_ENGINE_ID_MISMATCH");
    }
    if (response.security.username !== security.username) {
      throw new SnmpError("SNMPv3 response security name did not match", "SNMPV3_USERNAME_MISMATCH");
    }
    if (authKey && !verifyV3Message(responsePacket, authKey)) {
      throw new SnmpError("SNMPv3 response authentication failed", "SNMPV3_AUTHENTICATION_FAILED");
    }
    if (authKey) {
      const expectedEngineTime = currentEngineTime(engine);
      if (response.security.engineBoots !== engine.engineBoots || Math.abs(response.security.engineTime - expectedEngineTime) > 150) {
        throw new SnmpError("SNMPv3 response is outside the USM time window", "SNMPV3_NOT_IN_TIME_WINDOW");
      }
      engine.engineTime = response.security.engineTime;
      engine.discoveredAt = Date.now();
    }
    if (privacyKey) {
      if (!response.encryptedPdu) throw new SnmpError("SNMPv3 response was not DES encrypted", "SNMPV3_PRIVACY_REQUIRED");
      const plaintext = decryptScopedPdu(response.encryptedPdu, privacyKey, response.security.privacyParameters);
      response.scopedPdu = decodeScopedPdu(plaintext);
    } else if (response.encryptedPdu) {
      throw new SnmpError("Received encrypted SNMPv3 response without privacy credentials", "SNMPV3_PRIVACY_UNAVAILABLE");
    }
    if (!response.scopedPdu) throw new SnmpError("SNMPv3 response has no scoped PDU", "SNMPV3_SCOPED_PDU_MISSING");
    if (!equalBytes(response.scopedPdu.contextEngineId, engine.engineId) || response.scopedPdu.contextName !== (options.contextName ?? "")) {
      throw new SnmpError("SNMPv3 response context did not match", "SNMPV3_CONTEXT_MISMATCH");
    }
    if (response.scopedPdu.pdu.requestId !== requestId || response.scopedPdu.pdu.tag !== 0xa2) {
      throw new SnmpError("SNMPv3 response PDU did not match the request", "SNMPV3_PDU_MISMATCH");
    }
    return response.scopedPdu.pdu;
  }

  /** Discover and cache the remote authoritative engine ID and clock. */
  private async getAuthoritativeEngine(): Promise<EngineCache> {
    if (this.engine) return this.engine;
    if (this.engineDiscovery) return this.engineDiscovery;
    this.engineDiscovery = this.discoverEngine();
    try {
      this.engine = await this.engineDiscovery;
      return this.engine;
    } finally {
      this.engineDiscovery = undefined;
    }
  }

  /** Perform the standard unauthenticated SNMPv3 engine-ID discovery exchange. */
  private async discoverEngine(): Promise<EngineCache> {
    const requestId = this.nextRequestId();
    const messageId = this.nextMessageId();
    const emptyEngineId = new Uint8Array();
    const security: UsmParameters = {
      engineId: emptyEngineId,
      engineBoots: 0,
      engineTime: 0,
      username: "",
      authParameters: new Uint8Array(),
      privacyParameters: new Uint8Array(),
    };
    const pdu = encodeGetPdu(requestId, ["1.3.6.1.2.1.1.1.0"]);
    const scoped = encodeScopedPdu(emptyEngineId, "", pdu);
    const packet = encodeV3Message(
      { messageId, maxSize: MAX_MESSAGE_SIZE, flags: 0x04, securityModel: 3 },
      security,
      scoped,
    );
    const responsePacket = await this.transport.exchange(packet, (data) => isV3Response(data, messageId));
    const response = decodeV3Message(responsePacket);
    if (response.security.engineId.length < 5 || response.security.engineId.length > 32) {
      throw new SnmpError("SNMPv3 agent returned an invalid authoritative engine ID", "SNMPV3_ENGINE_ID_INVALID");
    }
    return {
      engineId: response.security.engineId,
      engineBoots: response.security.engineBoots,
      engineTime: response.security.engineTime,
      discoveredAt: Date.now(),
    };
  }

  /** Increment and wrap the SNMP PDU request identifier. */
  private nextRequestId(): number {
    this.requestId = this.requestId >= 2_147_483_647 ? 1 : this.requestId + 1;
    return this.requestId;
  }

  /** Increment and wrap the SNMPv3 message identifier. */
  private nextMessageId(): number {
    this.messageId = this.messageId >= 2_147_483_647 ? 1 : this.messageId + 1;
    return this.messageId;
  }

  /** Throw a typed response error when the agent indicates a PDU-level failure. */
  private assertSuccessfulResponse(response: DecodedPdu): void {
    if (response.firstField !== 0) throw createResponseError(response);
  }
}

/** Cached authoritative engine identity and local time estimate. */
interface EngineCache {
  /** Discovered authoritative engine ID. */
  engineId: Uint8Array;
  /** Engine boots value returned during discovery. */
  engineBoots: number;
  /** Engine time returned during discovery. */
  engineTime: number;
  /** Local timestamp when the engine clock was received. */
  discoveredAt: number;
}

/** Build a typed SNMP response error from PDU status and index fields. */
function createResponseError(response: DecodedPdu): SnmpResponseError {
  const names: Record<number, string> = {
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
  };
  return new SnmpResponseError(
    `SNMP agent returned ${names[response.firstField] ?? `error status ${response.firstField}`} at binding ${response.secondField}`,
    response.firstField,
    response.secondField,
  );
}

/** Match an SNMPv3 response using the message identifier in its outer header. */
function isV3Response(packet: Uint8Array, expectedMessageId: number): boolean {
  try {
    const message = decodeV3Message(packet);
    return message.header.messageId === expectedMessageId && message.header.securityModel === 3;
  } catch {
    return false;
  }
}

/** Decode a plaintext BER ScopedPDU after optional USM decryption. */
function decodeScopedPdu(encoded: Uint8Array): NonNullable<V3Message["scopedPdu"]> {
  const scoped = readTlv(encoded);
  expectTag(scoped, 0x30, "ScopedPDU");
  if (scoped.nextOffset !== encoded.length) throw new SnmpError("Trailing bytes after ScopedPDU", "SNMPV3_SCOPED_PDU_INVALID");
  const fields: ReturnType<typeof readTlv>[] = [];
  let offset = 0;
  while (offset < scoped.value.length) {
    const field = readTlv(scoped.value, offset);
    fields.push(field);
    offset = field.nextOffset;
  }
  if (fields.length !== 3) {
    throw new SnmpError("ScopedPDU must contain contextEngineID, contextName, and PDU", "SNMPV3_SCOPED_PDU_INVALID");
  }
  expectTag(fields[0]!, 0x04, "contextEngineID");
  expectTag(fields[1]!, 0x04, "contextName");
  return {
    contextEngineId: fields[0]!.value.slice(),
    contextName: new TextDecoder().decode(fields[1]!.value),
    pdu: decodePdu(fields[2]!),
  };
}

/** Estimate current authoritative engine time from the discovery timestamp. */
function currentEngineTime(engine: EngineCache): number {
  return Math.min(2_147_483_647, engine.engineTime + Math.floor((Date.now() - engine.discoveredAt) / 1_000));
}

/** Compare byte arrays without converting them to text. */
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return left.every((byte, index) => byte === right[index]);
}

/** Normalize an OID by removing optional leading and trailing dots. */
function normalizeOid(oid: Oid): string {
  return oid.replace(/^\.+|\.+$/g, "");
}

/** Determine whether an OID is the requested root or a descendant. */
function isWithinSubtree(root: string, oid: string): boolean {
  const normalized = normalizeOid(oid);
  return normalized === root || normalized.startsWith(`${root}.`);
}

/** Compare dotted-decimal OIDs by numeric arcs rather than string order. */
function compareOids(left: string, right: string): number {
  const leftArcs = normalizeOid(left).split(".").map(BigInt);
  const rightArcs = normalizeOid(right).split(".").map(BigInt);
  const sharedLength = Math.min(leftArcs.length, rightArcs.length);
  for (let index = 0; index < sharedLength; index++) {
    if (leftArcs[index]! < rightArcs[index]!) return -1;
    if (leftArcs[index]! > rightArcs[index]!) return 1;
  }
  return Math.sign(leftArcs.length - rightArcs.length);
}

/** Identify SNMP exception values that terminate a walk. */
function isEndOfWalk(binding: VarBind): boolean {
  return binding.type === "END_OF_MIB_VIEW" || binding.type === "NO_SUCH_OBJECT" || binding.type === "NO_SUCH_INSTANCE";
}

/** Validate protocol options before opening a UDP socket. */
function validateOptions(options: SnmpOptions): void {
  if (!options.host) throw new TypeError("SNMP host is required");
  if (options.port !== undefined && (!Number.isInteger(options.port) || options.port < 1 || options.port > 65_535)) {
    throw new RangeError("SNMP port must be an integer between 1 and 65535");
  }
  if (options.timeoutMs !== undefined && (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0)) {
    throw new RangeError("SNMP timeoutMs must be a positive number");
  }
  if (options.retries !== undefined && (!Number.isInteger(options.retries) || options.retries < 0)) {
    throw new RangeError("SNMP retries must be a non-negative integer");
  }
  if (options.version === "v3") {
    if (!options.security.username) throw new TypeError("SNMPv3 username is required");
    if (options.security.securityLevel !== "noAuthNoPriv" && !options.security.authPassword) {
      throw new TypeError("SNMPv3 authentication passphrase is required for this security level");
    }
    if (options.security.securityLevel === "authPriv" && !options.security.privacyPassword) {
      throw new TypeError("SNMPv3 privacy passphrase is required for authPriv");
    }
  }
}
