# tr-key-vault-client

Client library and command line client for the
[tr-key-vault](https://github.com/rinne/tr-key-vault) key vault
server: server-side JWT/JWE operations with vault-held keys over a
minimal JSON-over-POST API. The vault holds the key material; this
client only speaks the wire protocol — it performs no cryptography of
its own, has no runtime dependency for the library, and needs no
database.

## Install

```sh
npm install tr-key-vault-client
```

Node.js ≥ 18.

## Library

```js
const KeyVaultClient = require('tr-key-vault-client');

const kc = new KeyVaultClient({
	url: 'https://kv.example.com/',
	user: 'e4c2f918-b4b8-4fb7-8900-3a02f882c839',
	token: '96aecd9b-db39-483f-a04f-68b9ed7a3d80'
});

const { kid } = await kc.generateKey('ES256', { returnPublicKey: true });
const jwt = await kc.createJwt(kid, { sub: 'demo' });
const { header, data } = await kc.verifyJwt(jwt);
await kc.revokeKey(kid);
```

All methods are asynchronous. **Positional parameters are used only
for values fundamental to the operation** (the key id, the input
token, the payload, the algorithm); everything else goes into an
optional `options` object as the last parameter of every method.

### Constructor

```js
new KeyVaultClient({ url, user, token, timeout, insecure, ca, keepAlive })
```

| option | type | default | notes |
|---|---|---|---|
| `url` | string | (required) | Vault base URL. A trailing `/` and/or `/api/v1` suffix is accepted and normalized. |
| `user` | string (UUID) | — | Caller user id. Required for authenticated methods; optional for probe-only instances. |
| `token` | string (UUID) | — | Bearer token. Required for authenticated methods. |
| `timeout` | number | `30` | Request timeout in seconds (per-call override via `options.timeout`). |
| `insecure` | boolean | `false` | Skip TLS certificate verification (test setups only). |
| `ca` | string \| Buffer | — | PEM CA bundle to trust. |
| `keepAlive` | boolean | `true` | Per-instance keep-alive HTTP agents. |

Invalid options throw `TypeError`; unknown option keys are rejected.
The token is held in a private field and never appears in errors,
stack traces or when the instance is serialized.

### Methods

Every method takes a trailing `options` object; in addition to the
per-method properties below, all methods accept `op` (a UUID
correlation id, default random) and `timeout` (seconds).

| method | resolves with | ACL class |
|---|---|---|
| `hello(options)` | `{ uptime }` (authenticated liveness) | — |
| `generateKey(alg, options)` | `{ kid, key? }` — `options`: `kty`, `crv`, `keyLength`, `nbf`, `exp`, `acl`, `returnPublicKey` | — |
| `publicKey(kid, options)` | the public JWK | `export-public-key` |
| `createJwt(kid, payload, options)` | the compact JWT string | `sign` |
| `verifyJwt(token, options)` | `{ header, data }` — `options.kid` selects the key | `verify` |
| `createJwe(kid, data, options)` | the compact JWE string — `options.compress`: `false`\|`true`\|`'auto'` | `encrypt` |
| `decryptJwe(token, options)` | `{ header, data }` — `options.kid` | `decrypt` |
| `revokeKey(kid, options)` | `undefined` (hard delete) | `revoke-key` |
| `exportKey(kid, options)` | the full JWK (secret material) | `export-secret-key` (+ server `--allow-export-key`) |
| `listKeys(options)` | `[ { kid, kty, alg }, … ]` | — |
| `healthz(options)` / `readyz(options)` | `true` / `false` (unauthenticated probes) | — |
| `raw(request, data, options)` | the full response envelope, including error envelopes | — |

`raw()` is the escape hatch: it sends an arbitrary `request` name and
resolves with the whole `{ status, op, data }` (or error) envelope
rather than rejecting on an API-level error — useful for testing.

### Errors

```js
const { KeyVaultClientError, KeyVaultApiError,
        KeyVaultTransportError, KeyVaultProtocolError } = KeyVaultClient;
```

- **`TypeError`** — local usage errors (bad options, bad argument
  types, missing credentials).
- **`KeyVaultApiError`** — the vault returned a well-formed error
  (`status: "error"`); has `errorCode` (the server's registry) and
  `op`. `raw()` does not throw this — it returns the envelope.
- **`KeyVaultTransportError`** — network failure, timeout, TLS
  failure, non-JSON or otherwise unexpected response; may carry
  `cause`.
- **`KeyVaultProtocolError`** — a response that violates the protocol
  contract (e.g. an echoed `op` that doesn't match).

All three vault errors extend `KeyVaultClientError` (which extends
`Error`) for broad catching.

## kv-client

The package also ships `kv-client`, a command line client built on the
library: the vault API from the shell, pipe-friendly, configured via
options or `KV_CLIENT_OPT_*` environment variables. Run it from an
install, or straight through npx:

```sh
npx --package=tr-key-vault-client kv-client healthz --url https://kv.example.com/
```

```
kv-client [global-options] <command> [command-options] [args]
```

Connection/credentials: `--url`, `--user`, `--token` / `--token-file`
(or `KV_CLIENT_OPT_URL` / `_USER` / `_TOKEN` / `_TOKEN_FILE`).
Commands mirror the library: `healthcheck`, `generate-key`,
`public-key`, `create-jwt`, `verify-jwt`, `create-jwe`, `decrypt-jwe`,
`revoke-key`, `export-key`, `list-keys`, the unauthenticated
`healthz` / `readyz` probes, and `raw <request>`.

Payloads are supplied with `--data <json>` / `--data-file <path>` /
`--data -` (stdin); the token for `verify-jwt` / `decrypt-jwe` is a
positional argument (right after the command, or last) or stdin.
Output is pretty-printed JSON by default (`--compact-json` for one
line, `--raw` for the whole envelope, `--field <name>` for a single
field — a scalar bare, an object as JSON), so operations chain:

```sh
export KV_CLIENT_OPT_URL=https://kv.example.com/
export KV_CLIENT_OPT_USER=<user-id>
export KV_CLIENT_OPT_TOKEN=<token>

kid=$(kv-client generate-key --alg ES256 --field kid)
kv-client create-jwt --kid "$kid" --data '{"sub":"demo"}' --field token \
  | kv-client verify-jwt --kid "$kid"
```

Exit codes: `0` success, `1` local/usage error, `2` transport error
(couldn't reach the vault), `3` API operation error (the vault
returned `status: "error"`). `--insecure`/`-k` and `--ca-file` handle
a self-signed proxy in test setups.

## The vault

The server this client talks to — provisioning users, storing keys,
performing the crypto — is a separate project:
[github.com/rinne/tr-key-vault](https://github.com/rinne/tr-key-vault).
Users and tokens are issued there (with its `kv-admin` tool); this
package only consumes the HTTP API.

## Author and license

Copyright (c) 2026 Timo J. Rinne <tri@iki.fi>

MIT — see [`LICENSE`](LICENSE). (The tr-key-vault *server* is a
separate, independent project with its own license.)
