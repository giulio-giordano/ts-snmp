import assert from "node:assert/strict";
import { SnmpClient } from "ts-snmp";
import { decryptScopedPdu, encryptScopedPdu } from "../dist/protocol/usm.js";

assert.equal(typeof SnmpClient, "function", "the package should load through Node.js ESM");

const scopedPdu = Uint8Array.from([0x30, 0x06, 0x04, 0x04, 1, 2, 3, 4]);
const localizedKey = Uint8Array.from({ length: 20 }, (_, index) => index + 1);
const salt = Uint8Array.from({ length: 8 }, (_, index) => index);
const encrypted = encryptScopedPdu(scopedPdu, localizedKey, salt);
assert.deepEqual(decryptScopedPdu(encrypted, localizedKey, salt), scopedPdu);

console.log("Node.js ESM import and SNMPv3 DES-CBC smoke test passed.");
