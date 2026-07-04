'use strict';

// kv-client CLI tests: run the real binary as a subprocess against
// the stub vault.

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const path = require('node:path');

const { startStubVault } = require('./stubvault');

const ROOT = path.join(__dirname, '..');

let stub, baseEnv;

function client(args, opts) {
	const o = Object.assign({}, opts || {});
	return new Promise(function(resolve) {
		const child = execFile('node', [ path.join(ROOT, 'kv-client') ].concat(args),
								{ cwd: ROOT, env: Object.assign({}, baseEnv, o.env || {}) },
								function(err, stdout, stderr) {
									resolve({ code: (err ? (err.code ?? 1) : 0), stdout, stderr });
								});
		if (o.input !== undefined) {
			child.stdin.end(o.input);
		}
	});
}

test.before(async function() {
	stub = await startStubVault();
	baseEnv = Object.assign({}, process.env, {
		KV_CLIENT_OPT_URL: stub.url,
		KV_CLIENT_OPT_USER: stub.user,
		KV_CLIENT_OPT_TOKEN: stub.token
	});
});

test.after(async function() {
	if (stub) {
		await stub.close();
	}
});

test('probes and healthcheck', async function() {
	const hz = await client([ 'healthz' ]);
	assert.equal(hz.code, 0, hz.stderr);
	assert.match(hz.stdout, /"status": "ok"/);
	const rz = await client([ 'readyz' ]);
	assert.equal(rz.code, 0, rz.stderr);
	stub.setReady(false);
	const down = await client([ 'readyz' ]);
	assert.equal(down.code, 2);
	stub.setReady(true);
	const hc = await client([ 'healthcheck' ]);
	assert.equal(hc.code, 0, hc.stderr);
	assert.match(hc.stdout, /"uptime": 42/);
});

test('output modes: pretty default, --compact-json, --field, --raw', async function() {
	const pretty = await client([ 'healthcheck' ]);
	assert.ok(pretty.stdout.trim().split('\n').length > 1, 'pretty is multi-line');
	const compact = await client([ 'healthcheck', '--compact-json' ]);
	assert.equal(compact.stdout.trim(), '{"uptime":42}');
	const field = await client([ 'healthcheck', '--field', 'uptime' ]);
	assert.equal(field.stdout.trim(), '42');
	const raw = await client([ 'healthcheck', '--raw', '--compact-json' ]);
	assert.match(raw.stdout, /"status":"ok"/);
	assert.match(raw.stdout, /"op":"/);
	const missing = await client([ 'healthcheck', '--field', 'nope' ]);
	assert.equal(missing.code, 1);
});

test('generate-key with acl and --field kid; --field on an object', async function() {
	const gen = await client([ 'generate-key', '--alg', 'ES256', '--return-public-key',
							   '--acl', JSON.stringify({ [stub.user]: [ 'owner' ] }),
							   '--field', 'kid' ]);
	assert.equal(gen.code, 0, gen.stderr);
	assert.equal(gen.stdout.trim(), stub.fixedKid);
	// The stub saw the assembled operation data.
	assert.equal(stub.last().data.alg, 'ES256');
	assert.equal(stub.last().data.returnPublicKey, true);
	assert.ok(stub.last().data.acl);
	// --field on the JWK object prints JSON.
	const pk = await client([ 'public-key', '--kid', stub.fixedKid,
							  '--field', 'key', '--compact-json' ]);
	assert.equal(pk.code, 0, pk.stderr);
	assert.equal(JSON.parse(pk.stdout).kty, 'EC');
});

test('jwt pipeline: create-jwt --field token | verify-jwt -', async function() {
	const created = await client([ 'create-jwt', '--kid', stub.fixedKid,
								   '--data', JSON.stringify({ sub: 'pipe' }),
								   '--field', 'token' ]);
	assert.equal(created.code, 0, created.stderr);
	const token = created.stdout.trim();
	assert.match(token, /^ey/);
	const verified = await client([ 'verify-jwt', '--kid', stub.fixedKid, '-' ], { input: token });
	assert.equal(verified.code, 0, verified.stderr);
	assert.match(verified.stdout, /"sub": "pipe"/);
	assert.equal(stub.last().data.token, token);
});

test('jwe: payload from stdin, token positional, --compress', async function() {
	const enc = await client([ 'create-jwe', '--kid', stub.fixedKid, '--data', '-',
							   '--compress', 'auto', '--field', 'token' ],
							 { input: JSON.stringify({ secret: 42 }) });
	assert.equal(enc.code, 0, enc.stderr);
	assert.deepEqual(stub.last().data.data, { secret: 42 });
	assert.equal(stub.last().data.compress, 'auto');
	const dec = await client([ 'decrypt-jwe', '--kid', stub.fixedKid, enc.stdout.trim() ]);
	assert.equal(dec.code, 0, dec.stderr);
	assert.match(dec.stdout, /"secret": 42/);
	const badCompress = await client([ 'create-jwe', '--kid', stub.fixedKid,
									   '--data', '{}', '--compress', 'yes' ]);
	assert.equal(badCompress.code, 1);
});

test('list-keys, revoke-key, export-key', async function() {
	const list = await client([ 'list-keys', '--compact-json' ]);
	assert.equal(list.code, 0, list.stderr);
	assert.match(list.stdout, new RegExp(stub.fixedKid));
	const rev = await client([ 'revoke-key', '--kid', stub.fixedKid ]);
	assert.equal(rev.code, 0, rev.stderr);
	assert.match(rev.stdout, /"revoked": true/);
	const exp = await client([ 'export-key', '--kid', stub.fixedKid, '--field', 'key', '--compact-json' ]);
	assert.equal(exp.code, 0, exp.stderr);
	assert.equal(JSON.parse(exp.stdout).kty, 'oct');
});

test('raw escape hatch', async function() {
	const echo = await client([ 'raw', 'echo', '--data', JSON.stringify({ z: 9 }), '--compact-json' ]);
	assert.equal(echo.code, 0, echo.stderr);
	assert.match(echo.stdout, /"echo":\{"z":9\}/);
	const unknown = await client([ 'raw', 'no-such-op' ]);
	assert.equal(unknown.code, 3);
	assert.match(unknown.stderr, /API error 1002/);
});

test('exit codes: usage (1), api (3), transport (2)', async function() {
	const usage = await client([ 'public-key' ]);
	assert.equal(usage.code, 1);
	assert.match(usage.stderr, /requires --kid/);
	const noCmd = await client([]);
	assert.equal(noCmd.code, 1);
	const unknownCmd = await client([ 'frobnicate' ]);
	assert.equal(unknownCmd.code, 1);
	const api = await client([ 'raw', 'err-1104' ]);
	assert.equal(api.code, 3);
	assert.match(api.stderr, /API error 1104/);
	const transport = await client([ 'healthcheck' ],
								   { env: { KV_CLIENT_OPT_URL: 'http://127.0.0.1:1' } });
	assert.equal(transport.code, 2);
	// Protocol violations are transport-class failures (exit 2).
	const proto = await client([ 'raw', 'no-op-echo' ]);
	assert.equal(proto.code, 2);
});

test('auth failure is an API error (exit 3)', async function() {
	const bad = await client([ 'healthcheck' ],
							 { env: { KV_CLIENT_OPT_TOKEN: '11111111-2222-4333-8444-000000000000' } });
	assert.equal(bad.code, 3);
	assert.match(bad.stderr, /API error 1001/);
});

test('credentials not required for probes, required for operations', async function() {
	const env = { KV_CLIENT_OPT_USER: '', KV_CLIENT_OPT_TOKEN: '' };
	// Empty env values: optist env fallback yields empty strings which
	// fail the uuid callback for --user; drop them entirely instead.
	const bare = Object.assign({}, process.env, { KV_CLIENT_OPT_URL: stub.url });
	delete bare.KV_CLIENT_OPT_USER;
	delete bare.KV_CLIENT_OPT_TOKEN;
	const hz = await new Promise(function(resolve) {
		execFile('node', [ path.join(ROOT, 'kv-client'), 'healthz' ], { cwd: ROOT, env: bare },
				 function(err, stdout, stderr) {
					 resolve({ code: (err ? (err.code ?? 1) : 0), stdout, stderr });
				 });
	});
	assert.equal(hz.code, 0, hz.stderr);
	const op = await new Promise(function(resolve) {
		execFile('node', [ path.join(ROOT, 'kv-client'), 'healthcheck' ], { cwd: ROOT, env: bare },
				 function(err, stdout, stderr) {
					 resolve({ code: (err ? (err.code ?? 1) : 0), stdout, stderr });
				 });
	});
	assert.equal(op.code, 1);
	assert.match(op.stderr, /--user is required/);
});

test('--token-file', async function(t) {
	const fs = require('node:fs/promises');
	const os = require('node:os');
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvcli-'));
	t.after(async function() { await fs.rm(dir, { recursive: true, force: true }); });
	const tokenFile = path.join(dir, 'token');
	await fs.writeFile(tokenFile, stub.token + '\n');
	const env = Object.assign({}, process.env, {
		KV_CLIENT_OPT_URL: stub.url,
		KV_CLIENT_OPT_USER: stub.user
	});
	delete env.KV_CLIENT_OPT_TOKEN;
	const r = await new Promise(function(resolve) {
		execFile('node', [ path.join(ROOT, 'kv-client'), 'healthcheck', '--token-file', tokenFile ],
				 { cwd: ROOT, env },
				 function(err, stdout, stderr) {
					 resolve({ code: (err ? (err.code ?? 1) : 0), stdout, stderr });
				 });
	});
	assert.equal(r.code, 0, r.stderr);
});
