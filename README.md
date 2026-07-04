# tr-key-vault-client

Client library and command line client for the
[tr-key-vault](https://github.com/rinne/tr-key-vault) key vault
server: server-side JWT/JWE operations with vault-held keys over a
minimal JSON-over-POST API. The vault holds the key material; this
client only speaks the wire protocol — it performs no cryptography of
its own.

> **Status: pre-release (0.0.0).** The API below is the design being
> implemented; nothing works yet. The first functional release will be
> 0.1.0.

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

All methods are asynchronous. Positional parameters are used only for
values that are fundamental to the operation (the key id, the token,
the payload, the algorithm); everything else goes into an optional
`options` object as the last parameter.

Planned methods (one per vault API operation): `hello`, `generateKey`,
`publicKey`, `createJwt`, `verifyJwt`, `createJwe`, `decryptJwe`,
`revokeKey`, `exportKey`, `listKeys`, the unauthenticated `healthz` /
`readyz` probes, and a `raw` escape hatch for arbitrary requests.

## kv-client

The package will also ship the `kv-client` command line client
(relocated from the server repository), built on top of the library:
the vault API from the shell, pipe-friendly, configured via options or
`KV_CLIENT_OPT_*` environment variables. Installed or straight through
npx:

```sh
npx --package=tr-key-vault-client kv-client healthz --url https://kv.example.com/
```

## Requirements

Node.js ≥ 18. No runtime dependencies for the library itself.

The server project — the vault this client talks to — lives at
[github.com/rinne/tr-key-vault](https://github.com/rinne/tr-key-vault).

## Author and license

Copyright (c) 2026 Timo J. Rinne <tri@iki.fi>

MIT — see [`LICENSE`](LICENSE). (The tr-key-vault *server* is a
separate, independent project with its own license.)
