'use strict';

// TLS behavior: `insecure` and `ca` against a self-signed stub vault.
// The certificate is generated with the openssl CLI; the whole file
// is skipped when that fails (e.g. no openssl, or one too old for
// -addext).

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const execFileP = promisify(execFile);

const KeyVaultClient = require('../index');
const { KeyVaultTransportError } = KeyVaultClient;
const { startStubVault } = require('./stubvault');

let dir, stub, cert, haveTls = false;

test.before(async function() {
	dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvtls-'));
	try {
		await execFileP('openssl',
						[ 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
						  '-keyout', path.join(dir, 'key.pem'),
						  '-out', path.join(dir, 'cert.pem'),
						  '-days', '2', '-subj', '/CN=localhost',
						  '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1' ]);
		const key = await fs.readFile(path.join(dir, 'key.pem'));
		cert = await fs.readFile(path.join(dir, 'cert.pem'));
		stub = await startStubVault({ tls: { key, cert } });
		haveTls = true;
	} catch (e) {
		haveTls = false;
	}
});

test.after(async function() {
	if (stub) {
		await stub.close();
	}
	if (dir) {
		await fs.rm(dir, { recursive: true, force: true });
	}
});

test('self-signed cert: rejected by default, accepted with insecure, accepted with ca', async function(t) {
	if (! haveTls) {
		return t.skip('openssl not available for certificate generation');
	}
	// Default: certificate verification fails -> transport error.
	const strict = new KeyVaultClient({ url: stub.url, user: stub.user, token: stub.token,
										keepAlive: false });
	const e = await strict.hello().then(function() { return null; }, function(x) { return x; });
	assert.ok(e instanceof KeyVaultTransportError, String(e));
	// insecure: works.
	const loose = new KeyVaultClient({ url: stub.url, user: stub.user, token: stub.token,
									   insecure: true, keepAlive: false });
	assert.deepEqual(await loose.hello(), { uptime: 42 });
	// ca: works without insecure.
	const pinned = new KeyVaultClient({ url: stub.url, user: stub.user, token: stub.token,
										ca: cert, keepAlive: false });
	assert.deepEqual(await pinned.hello(), { uptime: 42 });
});

test('kv-client: -k and --ca-file against the self-signed stub', async function(t) {
	if (! haveTls) {
		return t.skip('openssl not available for certificate generation');
	}
	const ROOT = path.join(__dirname, '..');
	const env = Object.assign({}, process.env, {
		KV_CLIENT_OPT_URL: stub.url,
		KV_CLIENT_OPT_USER: stub.user,
		KV_CLIENT_OPT_TOKEN: stub.token
	});
	const run = function(args) {
		return new Promise(function(resolve) {
			execFile('node', [ path.join(ROOT, 'kv-client') ].concat(args), { cwd: ROOT, env },
					 function(err, stdout, stderr) {
						 resolve({ code: (err ? (err.code ?? 1) : 0), stdout, stderr });
					 });
		});
	};
	// Default: transport error (exit 2).
	assert.equal((await run([ 'healthcheck' ])).code, 2);
	// -k: works.
	const k = await run([ 'healthcheck', '-k' ]);
	assert.equal(k.code, 0, k.stderr);
	// --ca-file: works.
	const ca = await run([ 'healthcheck', '--ca-file', path.join(dir, 'cert.pem') ]);
	assert.equal(ca.code, 0, ca.stderr);
});
