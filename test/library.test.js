'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const KeyVaultClient = require('../index');
const { KeyVaultClientError, KeyVaultApiError, KeyVaultTransportError, KeyVaultProtocolError }
	  = KeyVaultClient;
const { startStubVault } = require('./stubvault');

let stub, kc;

test.before(async function() {
	stub = await startStubVault();
	kc = new KeyVaultClient({ url: stub.url, user: stub.user, token: stub.token });
});

test.after(async function() {
	if (stub) {
		await stub.close();
	}
});

test('constructor: validation', function() {
	assert.throws(function() { new KeyVaultClient(); }, TypeError);
	assert.throws(function() { new KeyVaultClient('http://x'); }, TypeError);
	assert.throws(function() { new KeyVaultClient({}); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: 'not a url' }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: 'ftp://x.example.com/' }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: stub.url, user: 'nope' }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: stub.url, token: 'nope' }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: stub.url, timeout: 0 }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: stub.url, timeout: 1.5 }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: stub.url, insecure: 'yes' }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: stub.url, ca: 42 }); }, TypeError);
	assert.throws(function() { new KeyVaultClient({ url: stub.url, keepAlive: 1 }); }, TypeError);
	// Unknown constructor options are rejected.
	assert.throws(function() { new KeyVaultClient({ url: stub.url, bogus: 1 }); },
				  /Unknown option/);
	// Probe-only instance (no credentials) is fine.
	assert.ok(new KeyVaultClient({ url: stub.url }));
});

test('url normalization: trailing slash and /api/v1 suffix', async function() {
	for (const url of [ stub.url, stub.url + '/', stub.url + '/api/v1', stub.url + '/api/v1/' ]) {
		const c = new KeyVaultClient({ url, user: stub.user, token: stub.token, keepAlive: false });
		const r = await c.hello();
		assert.deepEqual(r, { uptime: 42 }, url);
	}
});

test('hello resolves { uptime }', async function() {
	assert.deepEqual(await kc.hello(), { uptime: 42 });
});

test('probes resolve booleans', async function() {
	assert.equal(await kc.healthz(), true);
	assert.equal(await kc.readyz(), true);
	stub.setReady(false);
	assert.equal(await kc.readyz(), false);
	assert.equal(await kc.healthz(), true);
	stub.setReady(true);
	// Probes work without credentials.
	const bare = new KeyVaultClient({ url: stub.url, keepAlive: false });
	assert.equal(await bare.healthz(), true);
});

test('generateKey: forwards options, resolves { kid, key? }', async function() {
	const acl = { '22222222-3333-4444-8555-666666666666': [ 'verify' ] };
	const r = await kc.generateKey('ES256', { returnPublicKey: true, exp: 1999999999, acl });
	assert.equal(r.kid, stub.fixedKid);
	assert.equal(r.key.kty, 'EC');
	// The envelope carried exactly the operation data.
	const sent = stub.last();
	assert.equal(sent.request, 'generate-key');
	assert.deepEqual(sent.data, { alg: 'ES256', returnPublicKey: true, exp: 1999999999, acl });
	assert.equal(sent.user, stub.user);
	// alg is mandatory and positional.
	await assert.rejects(kc.generateKey(), TypeError);
	await assert.rejects(kc.generateKey(''), TypeError);
});

test('publicKey resolves the JWK', async function() {
	const jwk = await kc.publicKey(stub.fixedKid);
	assert.equal(jwk.kty, 'EC');
	assert.equal(jwk.kid, stub.fixedKid);
	await assert.rejects(kc.publicKey('not-a-kid'), TypeError);
});

test('createJwt resolves the token string; verifyJwt resolves { header, data }', async function() {
	const token = await kc.createJwt(stub.fixedKid, { sub: 'pipe' });
	assert.equal(typeof(token), 'string');
	assert.match(token, /^ey/);
	assert.deepEqual(stub.last().data, { kid: stub.fixedKid, data: { sub: 'pipe' } });
	const v = await kc.verifyJwt(token, { kid: stub.fixedKid });
	assert.equal(v.data.sub, 'pipe');
	assert.equal(v.header.alg, 'HS256');
	assert.deepEqual(stub.last().data, { token, kid: stub.fixedKid });
	// verifyJwt without kid omits it from the data.
	await kc.verifyJwt(token);
	assert.deepEqual(stub.last().data, { token });
	await assert.rejects(kc.createJwt(stub.fixedKid, 'not an object'), TypeError);
	await assert.rejects(kc.verifyJwt(''), TypeError);
	await assert.rejects(kc.verifyJwt(token, { kid: 'nope' }), TypeError);
});

test('createJwe/decryptJwe roundtrip shapes', async function() {
	const token = await kc.createJwe(stub.fixedKid, { secret: 42 }, { compress: 'auto' });
	assert.match(token, /^ey/);
	assert.deepEqual(stub.last().data, { kid: stub.fixedKid, data: { secret: 42 }, compress: 'auto' });
	const d = await kc.decryptJwe(token, { kid: stub.fixedKid });
	assert.deepEqual(d.data, { secret: 42 });
	// Any JSON value is a legal JWE payload; undefined is not.
	await kc.createJwe(stub.fixedKid, 'a plain string');
	assert.equal(stub.last().data.data, 'a plain string');
	await assert.rejects(kc.createJwe(stub.fixedKid, undefined), TypeError);
});

test('revokeKey resolves undefined; exportKey resolves the JWK; listKeys the array', async function() {
	assert.equal(await kc.revokeKey(stub.fixedKid), undefined);
	const jwk = await kc.exportKey(stub.fixedKid);
	assert.equal(jwk.kty, 'oct');
	assert.ok(jwk.k);
	const keys = await kc.listKeys();
	assert.ok(Array.isArray(keys));
	assert.equal(keys[0].kid, stub.fixedKid);
});

test('kid arguments are normalized to lower case', async function() {
	await kc.publicKey(stub.fixedKid.toUpperCase());
	assert.equal(stub.last().data.kid, stub.fixedKid);
	const token = 'ey.fake';
	await kc.verifyJwt(token, { kid: stub.fixedKid.toUpperCase() });
	assert.equal(stub.last().data.kid, stub.fixedKid);
});

test('per-call op and timeout options', async function() {
	const op = crypto.randomUUID().toUpperCase();
	await kc.hello({ op });
	assert.equal(stub.last().op, op.toLowerCase());
	await assert.rejects(kc.hello({ op: 'nope' }), TypeError);
	await assert.rejects(kc.hello({ timeout: 0 }), TypeError);
	await assert.rejects(kc.hello('options'), TypeError);
});

test('typed methods reject with KeyVaultApiError', async function() {
	// Every typed method funnels through the same internal API path;
	// an auth failure (wrong user, HTTP 403 with an error envelope)
	// exercises its rejection branch end to end.
	const bad = new KeyVaultClient({ url: stub.url,
									 user: '00000000-0000-4000-8000-000000000000',
									 token: stub.token,
									 keepAlive: false });
	const err = await bad.hello().then(function() { return null; }, function(e) { return e; });
	assert.ok(err instanceof KeyVaultApiError);
	assert.ok(err instanceof KeyVaultClientError);
	assert.equal(err.errorCode, 1001);
	assert.equal(typeof(err.message), 'string');
	assert.ok(err.op, 'the failed op id is carried on the error');
});

test('transport errors: non-JSON, non-envelope, refused connection, timeout', async function() {
	for (const op of [ 'bad-json', 'not-envelope' ]) {
		const e = await kc.raw(op, {}).then(function() { return null; }, function(x) { return x; });
		assert.ok(e instanceof KeyVaultTransportError, `${op}: ${e}`);
	}
	const refused = new KeyVaultClient({ url: 'http://127.0.0.1:1',
										 user: stub.user, token: stub.token, keepAlive: false });
	const e1 = await refused.hello().then(function() { return null; }, function(x) { return x; });
	assert.ok(e1 instanceof KeyVaultTransportError);
	const e1p = await refused.healthz().then(function() { return null; }, function(x) { return x; });
	assert.ok(e1p instanceof KeyVaultTransportError, 'probes reject on transport errors');
	// Timeout: the stub delays longer than the per-call timeout.
	const e2 = await kc.raw('slow', { delayMs: 3000 }, { timeout: 1 })
		  .then(function() { return null; }, function(x) { return x; });
	assert.ok(e2 instanceof KeyVaultTransportError);
	assert.match(e2.message, /timeout/);
});

test('protocol errors: op mismatch, missing op, bad data shape, malformed error', async function() {
	for (const op of [ 'no-op-echo', 'missing-op', 'data-not-object', 'malformed-error' ]) {
		const e = await kc.raw(op, {}).then(function() { return null; }, function(x) { return x; });
		assert.ok(e instanceof KeyVaultProtocolError, `${op}: ${e}`);
	}
});

test('raw: resolves error envelopes, resolves ok envelopes whole', async function() {
	const errEnv = await kc.raw('err-1101', {});
	assert.equal(errEnv.status, 'error');
	assert.equal(errEnv.errorCode, 1101);
	const okEnv = await kc.raw('echo', { x: 1 });
	assert.equal(okEnv.status, 'ok');
	assert.deepEqual(okEnv.data, { echo: { x: 1 } });
	assert.ok(okEnv.op);
	await assert.rejects(kc.raw('', {}), TypeError);
});

test('credentials required for authenticated methods', async function() {
	const bare = new KeyVaultClient({ url: stub.url, keepAlive: false });
	await assert.rejects(bare.hello(), TypeError);
	await assert.rejects(bare.listKeys(), TypeError);
});

test('the token never leaks into errors', async function() {
	const err = await kc.raw('err-1101', {}).then(function(envelope) {
		return new KeyVaultApiError(envelope.message, envelope.errorCode, envelope.op);
	});
	const refused = new KeyVaultClient({ url: 'http://127.0.0.1:1',
										 user: stub.user, token: stub.token, keepAlive: false });
	const e2 = await refused.hello().then(function() { return null; }, function(x) { return x; });
	for (const e of [ err, e2 ]) {
		const s = `${e.message} ${e.stack} ${JSON.stringify(Object.assign({}, e))}`;
		assert.ok(! s.includes(stub.token), 'no token in error');
	}
	// Nor via instance serialization.
	assert.ok(! JSON.stringify(Object.assign({}, kc)).includes(stub.token));
});
