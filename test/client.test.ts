import { expect, test } from "bun:test";
import { createSocket, type RemoteInfo, type Socket } from "node:dgram";
import { decodeCommunityMessage } from "../src/ber/decoder.ts";
import { encodeCommunityMessage, encodePdu, encodeOctetString } from "../src/ber/encoder.ts";
import { SnmpClient } from "../src/client/SnmpClient.ts";
import { decodeV3Message, encodeV3Message, encodeScopedPdu } from "../src/protocol/v3.ts";
import {
  authenticateV3Message,
  createDesSalt,
  decryptScopedPdu,
  encryptScopedPdu,
  passwordToLocalizedKey,
  verifyV3Message,
} from "../src/protocol/usm.ts";
import type { VarBind } from "../src/types.ts";

const walkValues: VarBind[] = [
  { oid: "1.3.6.1.2.1.1.1.0", type: "OCTET_STRING", value: new TextEncoder().encode("mock agent") },
  { oid: "1.3.6.1.2.1.1.2.0", type: "INTEGER", value: 42 },
  { oid: "1.3.6.1.2.1.2.1.0", type: "INTEGER", value: 8 },
];

/** Verify public Get and asynchronous Walk operations against a local v2c peer. */
test("SNMPv2c client performs get and streams a walk", async () => {
  const agent = await startCommunityAgent();
  const client = new SnmpClient({
    version: "v2c",
    host: "127.0.0.1",
    port: agent.port,
    community: "public",
    timeoutMs: 500,
    retries: 0,
  });

  try {
    const result = await client.get("1.3.6.1.2.1.1.1.0");
    expect(result.type).toBe("OCTET_STRING");
    if (result.type !== "OCTET_STRING") throw new Error("Expected an OCTET STRING binding");
    expect(new TextDecoder().decode(result.value)).toBe("mock agent");

    const bindings: VarBind[] = [];
    for await (const binding of client.walk("1.3.6.1.2.1.1")) bindings.push(binding);
    expect(bindings.map((binding) => binding.oid)).toEqual([
      "1.3.6.1.2.1.1.1.0",
      "1.3.6.1.2.1.1.2.0",
    ]);
  } finally {
    await client.close();
    await closeSocket(agent.socket);
  }
});

/** Verify the SNMPv1 walk uses GetNext and ends at the subtree boundary. */
test("SNMPv1 client walks with GetNext", async () => {
  const agent = await startCommunityAgent();
  const client = new SnmpClient({
    version: "v1",
    host: "127.0.0.1",
    port: agent.port,
    community: "public",
    timeoutMs: 500,
    retries: 0,
  });

  try {
    const bindings: VarBind[] = [];
    for await (const binding of client.walk("1.3.6.1.2.1.1")) bindings.push(binding);
    expect(bindings.map((binding) => binding.oid)).toEqual([
      "1.3.6.1.2.1.1.1.0",
      "1.3.6.1.2.1.1.2.0",
    ]);
  } finally {
    await client.close();
    await closeSocket(agent.socket);
  }
});

/** Verify v3 engine discovery, SHA-1 authentication, and DES privacy end to end. */
test("SNMPv3 authPriv client discovers the engine and performs get", async () => {
  const engineId = Uint8Array.of(0x80, 0, 0, 1, 0x10, 0x20, 0x30);
  const username = "test-user";
  const authKey = passwordToLocalizedKey("auth-passphrase", engineId);
  const privacyKey = passwordToLocalizedKey("privacy-passphrase", engineId);
  const agent = await startV3AuthPrivAgent(engineId, username, authKey, privacyKey);
  const client = new SnmpClient({
    version: "v3",
    host: "127.0.0.1",
    port: agent.port,
    timeoutMs: 1_000,
    retries: 0,
    security: {
      securityLevel: "authPriv",
      username,
      authPassword: "auth-passphrase",
      privacyPassword: "privacy-passphrase",
      authProtocol: "sha1",
      privacyProtocol: "des",
    },
  });

  try {
    const result = await client.get("1.3.6.1.2.1.1.1.0");
    expect(result.type).toBe("OCTET_STRING");
    if (result.type !== "OCTET_STRING") throw new Error("Expected an OCTET STRING binding");
    expect(new TextDecoder().decode(result.value)).toBe("secure agent");
  } finally {
    await client.close();
    await closeSocket(agent.socket);
  }
});

/** Verify transport timeouts reject rather than leave a pending operation. */
test("SNMP client rejects requests that time out", async () => {
  const socket = await createBoundSocket();
  const address = socket.address();
  if (typeof address === "string") throw new Error("Expected UDP address information");
  const client = new SnmpClient({
    version: "v2c",
    host: "127.0.0.1",
    port: address.port,
    community: "public",
    timeoutMs: 20,
    retries: 0,
  });

  try {
    await expect(client.get("1.3.6.1.2.1.1.1.0")).rejects.toThrow("No SNMP response");
  } finally {
    await client.close();
    await closeSocket(socket);
  }
});

/** Start a local community-based agent that implements Get, GetNext, and GetBulk. */
async function startCommunityAgent(): Promise<{ socket: Socket; port: number }> {
  const socket = await createBoundSocket();
  socket.on("message", (packet, remote) => {
    try {
      const request = decodeCommunityMessage(packet);
      const cursor = request.pdu.bindings[0]?.oid ?? "0.0";
      let bindings: VarBind[];

      if (request.pdu.tag === 0xa0) {
        bindings = [walkValues.find((binding) => binding.oid === cursor) ?? walkValues[0]!];
      } else {
        const matches = walkValues.filter((binding) => compareOids(binding.oid, cursor) > 0);
        const limit = request.pdu.tag === 0xa5 ? request.pdu.secondField : 1;
        bindings = matches.slice(0, Math.max(1, limit));
        if (bindings.length === 0) {
          if (request.version === 0) {
            replyCommunity(socket, remote, request.version, request.community, request.pdu.requestId, 2, 1, []);
            return;
          }
          bindings = [{ oid: cursor, type: "END_OF_MIB_VIEW", value: null }];
        }
      }

      replyCommunity(socket, remote, request.version, request.community, request.pdu.requestId, 0, 0, bindings);
    } catch {
      // Ignore malformed test datagrams so the client exercises its normal timeout path.
    }
  });
  const address = socket.address();
  if (typeof address === "string") throw new Error("Expected UDP address information");
  return { socket, port: address.port };
}

/** Bind a local UDP socket to an ephemeral loopback port. */
async function createBoundSocket(): Promise<Socket> {
  const socket = createSocket("udp4");
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      socket.off("error", reject);
      resolve();
    });
  });
  return socket;
}

/** Send a community response PDU to the requester. */
function replyCommunity(
  socket: Socket,
  remote: RemoteInfo,
  version: 0 | 1,
  community: string,
  requestId: number,
  errorStatus: number,
  errorIndex: number,
  bindings: VarBind[],
): void {
  const response = encodeCommunityMessage(version, community, encodePdu(0xa2, requestId, errorStatus, errorIndex, bindings));
  socket.send(response, remote.port, remote.address);
}

/** Start an SNMPv3 test agent that authenticates and decrypts authPriv requests. */
async function startV3AuthPrivAgent(
  engineId: Uint8Array,
  username: string,
  authKey: Uint8Array,
  privacyKey: Uint8Array,
): Promise<{ socket: Socket; port: number }> {
  const socket = await createBoundSocket();
  let saltCounter = 100;
  socket.on("message", (packet, remote) => {
    try {
      const request = decodeV3Message(packet);
      if (request.security.engineId.length === 0) {
        const requestId = request.scopedPdu?.pdu.requestId ?? 1;
        const discoveryReport = encodePdu(0xa8, requestId, 0, 0, []);
        const response = encodeV3Message(
          { messageId: request.header.messageId, maxSize: 65_507, flags: 0, securityModel: 3 },
          {
            engineId,
            engineBoots: 1,
            engineTime: 50,
            username: "",
            authParameters: new Uint8Array(),
            privacyParameters: new Uint8Array(),
          },
          encodeScopedPdu(engineId, "", discoveryReport),
        );
        socket.send(response, remote.port, remote.address);
        return;
      }

      if (!verifyV3Message(packet, authKey) || !request.encryptedPdu) return;
      const clearScoped = decryptScopedPdu(request.encryptedPdu, privacyKey, request.security.privacyParameters);
      const scoped = decodeV3Message(encodeV3Message(
        { messageId: request.header.messageId, maxSize: 65_507, flags: 0, securityModel: 3 },
        request.security,
        clearScoped,
      )).scopedPdu;
      if (!scoped || request.security.username !== username) return;

      const responsePdu = encodePdu(0xa2, scoped.pdu.requestId, 0, 0, [
        { oid: "1.3.6.1.2.1.1.1.0", type: "OCTET_STRING", value: new TextEncoder().encode("secure agent") },
      ]);
      const salt = createDesSalt(1, saltCounter++);
      const responseScoped = encodeScopedPdu(engineId, scoped.contextName, responsePdu);
      const encrypted = encryptScopedPdu(responseScoped, privacyKey, salt);
      const response = encodeV3Message(
        { messageId: request.header.messageId, maxSize: 65_507, flags: 0x03, securityModel: 3 },
        {
          engineId,
          engineBoots: 1,
          engineTime: 51,
          username,
          authParameters: new Uint8Array(12),
          privacyParameters: salt,
        },
        encodeOctetString(encrypted),
      );
      authenticateV3Message(response, authKey);
      socket.send(response, remote.port, remote.address);
    } catch {
      // Ignore malformed or unauthenticated packets in the test agent.
    }
  });
  const address = socket.address();
  if (typeof address === "string") throw new Error("Expected UDP address information");
  return { socket, port: address.port };
}

/** Close a UDP socket and wait for its close callback. */
async function closeSocket(socket: Socket): Promise<void> {
  await new Promise<void>((resolve) => socket.close(() => resolve()));
}

/** Compare dotted OIDs by their numeric arcs. */
function compareOids(left: string, right: string): number {
  const leftArcs = left.split(".").map(BigInt);
  const rightArcs = right.split(".").map(BigInt);
  for (let index = 0; index < Math.min(leftArcs.length, rightArcs.length); index++) {
    if (leftArcs[index]! < rightArcs[index]!) return -1;
    if (leftArcs[index]! > rightArcs[index]!) return 1;
  }
  return Math.sign(leftArcs.length - rightArcs.length);
}
