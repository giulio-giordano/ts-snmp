import des from "des.js";
import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { concatenate } from "../ber/encoder.ts";
import { readChildren, readTlv } from "../ber/decoder.ts";
import { SnmpError } from "../types.ts";

/** USM authentication digest length for HMAC-SHA-1-96. */
export const SHA1_AUTH_PARAMETERS_LENGTH = 12;

/** Pure-JavaScript DES-CBC so SNMPv3 privacy works with Node's default OpenSSL config. */
const DesCbc = des.CBC.instantiate(des.DES);

/** Derive a localized USM key from a passphrase and authoritative engine ID. */
export function passwordToLocalizedKey(passphrase: string, engineId: Uint8Array): Uint8Array {
  const passwordBytes = new TextEncoder().encode(passphrase);
  if (passwordBytes.length < 8) throw new SnmpError("SNMPv3 USM passphrases must contain at least 8 UTF-8 bytes", "SNMPV3_WEAK_PASSPHRASE");
  if (engineId.length === 0) throw new SnmpError("SNMPv3 engine ID is required to localize a USM key", "SNMPV3_ENGINE_ID_REQUIRED");

  // RFC 3414 hashes the passphrase repeated to exactly one mebibyte.
  const hash = createHash("sha1");
  const chunk = new Uint8Array(4096);
  for (let offset = 0; offset < 1_048_576; offset += chunk.length) {
    for (let index = 0; index < chunk.length; index++) {
      chunk[index] = passwordBytes[(offset + index) % passwordBytes.length]!;
    }
    hash.update(chunk);
  }

  const ku = new Uint8Array(hash.digest());
  const localizationHash = createHash("sha1");
  localizationHash.update(ku);
  localizationHash.update(engineId);
  localizationHash.update(ku);
  return new Uint8Array(localizationHash.digest());
}

/** Insert the RFC 3414 HMAC-SHA-1-96 digest into an encoded SNMPv3 message. */
export function authenticateV3Message(packet: Uint8Array, localizedKey: Uint8Array): Uint8Array {
  const range = locateAuthParameters(packet);
  if (range.length !== SHA1_AUTH_PARAMETERS_LENGTH) {
    throw new SnmpError("SNMPv3 SHA-1 authParameters must be 12 bytes", "SNMPV3_AUTH_FIELD_INVALID");
  }
  const unsigned = new Uint8Array(packet);
  unsigned.fill(0, range.offset, range.offset + range.length);
  const digest = new Uint8Array(createHmac("sha1", localizedKey).update(unsigned).digest());
  packet.set(digest.subarray(0, SHA1_AUTH_PARAMETERS_LENGTH), range.offset);
  return packet;
}

/** Verify an incoming SNMPv3 HMAC-SHA-1-96 authentication digest. */
export function verifyV3Message(packet: Uint8Array, localizedKey: Uint8Array): boolean {
  const range = locateAuthParameters(packet);
  if (range.length !== SHA1_AUTH_PARAMETERS_LENGTH) return false;
  const actual = new Uint8Array(packet.subarray(range.offset, range.offset + range.length));
  const unsigned = new Uint8Array(packet);
  unsigned.fill(0, range.offset, range.offset + range.length);
  const expected = new Uint8Array(createHmac("sha1", localizedKey).update(unsigned).digest()).subarray(0, range.length);
  return timingSafeEqual(actual, expected);
}

/** Create a randomized starting point for the local USM DES salt counter. */
export function createInitialDesSaltCounter(): number {
  return randomBytes(4).readUInt32BE(0) % 0xffff_ffff;
}

/**
 * Encode the RFC 3414 DES privacy salt as engineBoots followed by a local
 * monotonically increasing 32-bit integer, both in network byte order.
 */
export function createDesSalt(engineBoots: number, localCounter: number): Uint8Array {
  if (!Number.isInteger(engineBoots) || engineBoots < 0 || engineBoots > 0xffff_ffff) {
    throw new RangeError("SNMPv3 engineBoots must fit in an unsigned 32-bit integer");
  }
  if (!Number.isInteger(localCounter) || localCounter < 0 || localCounter > 0xffff_ffff) {
    throw new RangeError("SNMPv3 DES salt counter must fit in an unsigned 32-bit integer");
  }
  const salt = new Uint8Array(8);
  const view = new DataView(salt.buffer);
  view.setUint32(0, engineBoots);
  view.setUint32(4, localCounter);
  return salt;
}

/** Encrypt a BER-encoded SNMPv3 ScopedPDU with USM DES-CBC privacy. */
export function encryptScopedPdu(scopedPdu: Uint8Array, localizedPrivacyKey: Uint8Array, salt: Uint8Array): Uint8Array {
  const { key, iv } = desKeyAndIv(localizedPrivacyKey, salt);
  const paddingLength = (8 - (scopedPdu.length % 8)) % 8;
  const padding = paddingLength === 0 ? new Uint8Array() : new Uint8Array(randomBytes(paddingLength));
  const padded = paddingLength === 0 ? scopedPdu : concatenate([scopedPdu, padding]);
  const cipher = DesCbc.create({ type: "encrypt", key, iv, padding: false });
  return Uint8Array.from(cipher.update(padded).concat(cipher.final()));
}

/** Decrypt an SNMPv3 DES-CBC ScopedPDU and remove BER-block padding. */
export function decryptScopedPdu(ciphertext: Uint8Array, localizedPrivacyKey: Uint8Array, salt: Uint8Array): Uint8Array {
  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new SnmpError("SNMPv3 DES ciphertext length must be a positive multiple of eight", "SNMPV3_CIPHERTEXT_INVALID");
  }
  const { key, iv } = desKeyAndIv(localizedPrivacyKey, salt);
  const decipher = DesCbc.create({ type: "decrypt", key, iv, padding: false });
  const plaintext = Uint8Array.from(decipher.update(ciphertext).concat(decipher.final()));
  const scopedTlv = readTlv(plaintext);
  if (scopedTlv.tag !== 0x30) throw new SnmpError("Decrypted SNMPv3 data is not a ScopedPDU", "SNMPV3_SCOPED_PDU_INVALID");
  return plaintext.slice(0, scopedTlv.nextOffset);
}

/** Locate authParameters within the nested BER SNMPv3 securityParameters. */
function locateAuthParameters(packet: Uint8Array): { offset: number; length: number } {
  const message = readTlv(packet);
  if (message.tag !== 0x30) throw new SnmpError("SNMPv3 message must be a BER SEQUENCE", "SNMPV3_MESSAGE_INVALID");
  const messageFields = readChildren(message.value);
  if (messageFields.length !== 4 || messageFields[2]!.tag !== 0x04) {
    throw new SnmpError("SNMPv3 securityParameters field is malformed", "SNMPV3_MESSAGE_INVALID");
  }

  const securityTlv = messageFields[2]!;
  const usmSequence = readTlv(securityTlv.value);
  if (usmSequence.tag !== 0x30) throw new SnmpError("SNMPv3 USM parameters must be a BER SEQUENCE", "SNMPV3_MESSAGE_INVALID");
  const usmFields = readChildren(usmSequence.value);
  if (usmFields.length !== 6 || usmFields[4]!.tag !== 0x04) {
    throw new SnmpError("SNMPv3 authParameters field is malformed", "SNMPV3_MESSAGE_INVALID");
  }

  const authField = usmFields[4]!;
  return {
    offset: message.valueOffset + securityTlv.valueOffset + usmSequence.valueOffset + authField.valueOffset,
    length: authField.value.length,
  };
}

/** Derive the DES key and IV from localized privacy key and salt. */
function desKeyAndIv(localizedKey: Uint8Array, salt: Uint8Array): { key: Uint8Array; iv: Uint8Array } {
  if (localizedKey.length < 16) throw new SnmpError("Localized DES privacy key must contain at least 16 bytes", "SNMPV3_PRIVACY_KEY_INVALID");
  if (salt.length !== 8) throw new SnmpError("SNMPv3 DES privacy salt must contain eight bytes", "SNMPV3_PRIVACY_SALT_INVALID");
  const key = localizedKey.slice(0, 8);
  const iv = new Uint8Array(8);
  for (let index = 0; index < iv.length; index++) iv[index] = localizedKey[index + 8]! ^ salt[index]!;
  return { key, iv };
}
