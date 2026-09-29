# ts-snmp

A standalone TypeScript SNMP client library for **Node.js 20+** and [Bun](https://bun.sh). It speaks **SNMPv1**, **SNMPv2c**, and **SNMPv3 (USM)** over UDP, with minimal runtime dependencies, typed bindings, and a streaming `walk()` API designed for large subtrees.

```
Agent (UDP:161)
   ▲                    ┌───────────────────────────────┐
   │ UDP datagrams      │ ts-snmp                        │
   │ (BER-encoded)      │  ber/      ── BER codec        │
   ├────────────────────►  protocol/ ── v1, v2c, v3, USM │
   │                    │  transport/─ UDP + retry/timeout│
   │                    │  client/   ── get(), walk()    │
   └────────────────────┤                               │
                        └───────────────────────────────┘
```

The companion browser/Tauri application [snmp-console](../snmp-console) is built on this package and consumes it as a local `file:` dependency.

## Features

- **SNMPv1** and **SNMPv2c** with community strings.
- **SNMPv3 USM** at all three security levels: `noAuthNoPriv`, `authNoPriv`, and `authPriv`.
- SNMPv3 **SHA-1** authentication (HMAC-SHA-1-96) and **DES** privacy, including RFC 3414 key localization, authoritative engine discovery, and engine-clock/salt management.
- **`get(oid)`** returns a typed `{ oid, type, value }` binding and verifies the agent returned the requested OID.
- **`walk(rootOid)`** is an `AsyncIterable<VarBind>` — bindings are yielded the moment each SNMP response arrives, so arbitrarily large subtrees can be consumed incrementally without buffering everything in memory.
- **GetBulk** batching for v2c/v3 (`max-repetitions = 10`); serial `GetNext` for v1.
- Walk termination handled defensively: `endOfMibView`/`noSuch*` exceptions, leaving the requested subtree, and a no-progress guard that catches misbehaving agents.
- UDP **timeout and retry** policy (defaults: port 161, 1000 ms, 1 retry) with request/response correlation per datagram.
- Uses Node.js built-in UDP and crypto APIs, plus a small pure-JavaScript DES implementation so SNMPv3 privacy works without enabling OpenSSL's legacy provider.

## Installation

```sh
npm install ts-snmp
# or
bun add ts-snmp
```

The package publishes compiled JavaScript and TypeScript declarations, so Node.js consumers do not need Bun or a TypeScript runtime. If you use this repository directly:

```sh
bun install
bun test
bun run typecheck
bun run build
npm run test:node
```

## Usage

### SNMPv1 / SNMPv2c

```ts
import { SnmpClient } from "ts-snmp";

const snmp = new SnmpClient({
  version: "v2c",
  host: "192.0.2.10",
  community: "public",
  timeoutMs: 1500,
  retries: 2,
});

try {
  const systemName = await snmp.get("1.3.6.1.2.1.1.5.0");
  console.log(systemName.oid, systemName.type, systemName.value);

  // Walk results stream in as they arrive.
  for await (const binding of snmp.walk("1.3.6.1.2.1.1")) {
    console.log(binding.oid, binding.type, binding.value);
  }
} finally {
  await snmp.close();
}
```

### SNMPv3 (USM)

```ts
import { SnmpClient } from "ts-snmp";

const snmp = new SnmpClient({
  version: "v3",
  host: "192.0.2.10",
  security: {
    securityLevel: "authPriv",
    username: "monitor",
    authPassword: "at-least-eight-bytes",
    privacyPassword: "another-eight-bytes",
    authProtocol: "sha1",
    privacyProtocol: "des",
  },
});

try {
  console.log(await snmp.get("1.3.6.1.2.1.1.3.0"));
} finally {
  await snmp.close();
}
```

For `noAuthNoPriv` or `authNoPriv`, provide the matching `security` object without the unneeded fields. An optional `contextName` can be added for v3 requests.

## API overview

### `new SnmpClient(options)`

| Option | Default | Notes |
| ------ | ------- | ----- |
| `host` | — | Agent IPv4/IPv6 address or hostname. |
| `port` | `161` | Agent UDP port. |
| `timeoutMs` | `1000` | Timeout for each send attempt. |
| `retries` | `1` | Retries after the initial attempt. |
| `version` | — | `"v1"`, `"v2c"`, or `"v3"`. |
| `community` | — | v1/v2c community string. |
| `security` | — | v3 USM credentials and security level. |

### Methods

- **`get(oid: Oid): Promise<VarBind>`** — read one scalar. Throws on error status, OID mismatch, or an unexpected binding count.
- **`walk(rootOid: Oid): AsyncIterable<VarBind>`** — iterate the subtree under `rootOid`.
- **`close(): Promise<void>`** — release the UDP socket.

### Errors

All errors extend `SnmpError` with a stable machine-readable `code`:

- `SnmpTimeoutError` — no matching response within `timeoutMs` after all retries.
- `SnmpResponseError` — the agent returned a PDU error status (`tooBig`, `noSuchName`, `genErr`, …) with the failing binding index.
- `SnmpError` — protocol-level failures (walk no-progress, v3 USM mismatches, transport closed, invalid options, …).

## Binding value types

`VarBind` is a discriminated union keyed by the `type` field:

| `type` | `value` |
| ------ | ------- |
| `INTEGER` | `number` |
| `OCTET_STRING` | `Uint8Array` (raw bytes) |
| `OBJECT_IDENTIFIER` | `string` (dotted decimal) |
| `NULL` | `null` |
| `IP_ADDRESS` | `string` (dotted decimal IPv4) |
| `COUNTER32` | `number` |
| `GAUGE32` / `UNSIGNED32` | `number` |
| `TIME_TICKS` | `number` (hundredths of a second) |
| `OPAQUE` | `Uint8Array` (raw bytes) |
| `COUNTER64` | `bigint` (full 64-bit range preserved) |
| `NO_SUCH_OBJECT` / `NO_SUCH_INSTANCE` / `END_OF_MIB_VIEW` | exception value (terminates walks) |

## Architecture

- **`src/ber/`** — minimal BER codec: TLV reader/writer, OID and length encoding, integer/unsigned/bigint handling.
- **`src/protocol/`** — version-specific message serialization: v1, v2c, Get/GetBulk PDUs, SNMPv3 wrapping, and the USM security module (key localization, HMAC-SHA-1, DES, salt counters).
- **`src/transport/`** — `UdpTransport` abstraction owning a single UDP socket, correlating responses via protocol-level matchers, and applying the timeout/retry policy without embedding SNMP details.
- **`src/client/`** — `SnmpClient`: coordinates protocol + transport for `get()` and the streaming `walk()`.

## Project layout

```
src/
  ber/          BER TLV encoder/decoder
  protocol/     v1, v2c, v3, USM security, PDUs
  transport/    UDP socket, response matching, retries
  client/       SnmpClient (get, walk, close)
  types.ts      options, typed VarBind union, errors
  index.ts      public package exports
test/           BER, protocol, and client test suites
../snmp-console Companion UI application (browser + Tauri)
```

## Security notes

- SNMPv1/v2c community strings are sent in clear text over UDP.
- SNMPv3 support uses **SHA-1** and **DES**, both legacy algorithms — adequate only where necessity or compatibility demands them. Prefer stronger USM algorithms or SNMPv3 over a protected network path.
- Passphrases must be at least 8 bytes (RFC 3414) and are localized to the agent's authoritative engine ID; the DES private key is never reused across messages thanks to salted encryption.

## Credits

This code was written by **GPT-6 Luna**. 🚀