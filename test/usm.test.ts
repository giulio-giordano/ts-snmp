import { expect, test } from "bun:test";
import { encodeGetPdu } from "../src/protocol/pdu.ts";
import { decodeV3Message, encodeScopedPdu, encodeV3Message } from "../src/protocol/v3.ts";
import {
  authenticateV3Message,
  createDesSalt,
  decryptScopedPdu,
  encryptScopedPdu,
  passwordToLocalizedKey,
  verifyV3Message,
} from "../src/protocol/usm.ts";
import { encodeOctetString } from "../src/ber/encoder.ts";

/** Verify SHA-1 USM passphrase localization against the RFC 3414 example. */
test("USM SHA-1 passphrase localization matches the RFC example", () => {
  const engineId = Uint8Array.from(Buffer.from("000000000000000000000002", "hex"));
  const localizedKey = passwordToLocalizedKey("maplesyrup", engineId);
  expect(Buffer.from(localizedKey).toString("hex")).toBe("6695febc9288e36282235fc7151f128497b38f3f");
});

/** Verify HMAC-SHA-1-96 signing and reject a changed message. */
test("USM SHA-1 authentication signs and verifies SNMPv3 messages", () => {
  const engineId = Uint8Array.of(0x80, 0, 0, 1, 2, 3);
  const authKey = passwordToLocalizedKey("auth-passphrase", engineId);
  const pdu = encodeGetPdu(4, ["1.3.6.1.2.1.1.1.0"]);
  const packet = encodeV3Message(
    { messageId: 4, maxSize: 65_507, flags: 5, securityModel: 3 },
    {
      engineId,
      engineBoots: 1,
      engineTime: 5,
      username: "user",
      authParameters: new Uint8Array(12),
      privacyParameters: new Uint8Array(),
    },
    encodeScopedPdu(engineId, "", pdu),
  );

  authenticateV3Message(packet, authKey);
  expect(verifyV3Message(packet, authKey)).toBe(true);
  const receivedBuffer = Buffer.from(packet);
  expect(verifyV3Message(receivedBuffer, authKey)).toBe(true);
  expect(Buffer.from(packet)).toEqual(receivedBuffer);
  const changed = packet.slice();
  changed[changed.length - 1] = changed[changed.length - 1]! ^ 0x01;
  expect(verifyV3Message(changed, authKey)).toBe(false);
});

/** Verify DES salt structure and scoped-PDU encryption/decryption round-trip. */
test("USM DES privacy encrypts a scoped PDU with an RFC-formatted salt", () => {
  const engineId = Uint8Array.of(0x80, 0, 0, 1, 2, 3);
  const privacyKey = passwordToLocalizedKey("privacy-passphrase", engineId);
  const salt = createDesSalt(7, 42);
  expect([...salt]).toEqual([0, 0, 0, 7, 0, 0, 0, 42]);

  const scoped = encodeScopedPdu(engineId, "context", encodeGetPdu(8, ["1.3.6.1.2.1.1.1.0"]));
  const ciphertext = encryptScopedPdu(scoped, privacyKey, salt);
  expect(ciphertext.length % 8).toBe(0);
  const plaintext = decryptScopedPdu(ciphertext, privacyKey, salt);
  expect([...plaintext]).toEqual([...scoped]);

  const encryptedMessage = encodeV3Message(
    { messageId: 8, maxSize: 65_507, flags: 7, securityModel: 3 },
    {
      engineId,
      engineBoots: 7,
      engineTime: 10,
      username: "user",
      authParameters: new Uint8Array(12),
      privacyParameters: salt,
    },
    encodeOctetString(ciphertext),
  );
  expect(decodeV3Message(encryptedMessage).encryptedPdu).toEqual(ciphertext);
});
