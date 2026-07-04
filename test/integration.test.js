'use strict';

// Optional integration suite against a LIVE tr-key-vault. Runs only
// when the environment provides a vault and credentials:
//
//   KV_CLIENT_TEST_URL=https://vault.example.com
//   KV_CLIENT_TEST_USER=<user-uuid>
//   KV_CLIENT_TEST_TOKEN=<token-uuid>
//
// Skipped entirely otherwise. Creates keys with a short expiry as a
// safety net and revokes everything it created.

const test = require('node:test');
const assert = require('node:assert/strict');

const KeyVaultClient = require('../index');
const { KeyVaultApiError } = KeyVaultClient;

const URL_ = process.env.KV_CLIENT_TEST_URL;
const USER = process.env.KV_CLIENT_TEST_USER;
const TOKEN = process.env.KV_CLIENT_TEST_TOKEN;
const enabled = !! (URL_ && USER && TOKEN);

let kc;
const createdKids = [];

test.before(function() {
	if (! enabled) {
		return;
	}
	kc = new KeyVaultClient({ url: URL_, user: USER, token: TOKEN });
});

test.after(async function() {
	if (! enabled) {
		return;
	}
	for (const kid of createdKids) {
		try {
			await kc.revokeKey(kid);
		} catch (_) { /* already revoked or expired */ }
	}
});

async function generate(alg, options) {
	const r = await kc.generateKey(alg, Object.assign({ exp: Math.floor(Date.now() / 1000) + 600 },
													  options || {}));
	createdKids.push(r.kid);
	return r;
}

test('live: probes and hello', async function(t) {
	if (! enabled) { return t.skip('no live vault configured'); }
	assert.equal(await kc.healthz(), true);
	assert.equal(await kc.readyz(), true);
	const h = await kc.hello();
	assert.ok(Number.isSafeInteger(h.uptime));
});

test('live: JWT roundtrip with a generated HS256 key', async function(t) {
	if (! enabled) { return t.skip('no live vault configured'); }
	const { kid } = await generate('HS256');
	const token = await kc.createJwt(kid, { sub: 'integration', n: 1 });
	const v = await kc.verifyJwt(token);
	assert.equal(v.data.sub, 'integration');
	assert.equal(v.header.kid, kid);
	assert.equal(v.header.alg, 'HS256');
});

test('live: JWE roundtrip and public key with ECDH-ES', async function(t) {
	if (! enabled) { return t.skip('no live vault configured'); }
	const { kid, key } = await generate('ECDH-ES', { returnPublicKey: true });
	assert.equal(key.kty, 'EC');
	assert.equal(key.d, undefined);
	const jwk = await kc.publicKey(kid);
	assert.deepEqual(jwk, key);
	const token = await kc.createJwe(kid, { secret: 'live', arr: [ 1, 2, 3 ] }, { compress: 'auto' });
	const d = await kc.decryptJwe(token);
	assert.deepEqual(d.data, { secret: 'live', arr: [ 1, 2, 3 ] });
	assert.equal(d.header.kid, kid);
});

test('live: listKeys, revoke, masking after revoke', async function(t) {
	if (! enabled) { return t.skip('no live vault configured'); }
	const { kid } = await generate('A256GCMKW');
	const keys = await kc.listKeys();
	assert.ok(keys.some(function(k) { return k.kid === kid; }));
	await kc.revokeKey(kid);
	const err = await kc.createJwe(kid, { x: 1 })
		  .then(function() { return null; }, function(e) { return e; });
	assert.ok(err instanceof KeyVaultApiError);
	assert.equal(err.errorCode, 1101);
});

test('live: API error surfaces (unknown operation via raw)', async function(t) {
	if (! enabled) { return t.skip('no live vault configured'); }
	const envelope = await kc.raw('no-such-operation', {});
	assert.equal(envelope.status, 'error');
	assert.equal(envelope.errorCode, 1002);
});
