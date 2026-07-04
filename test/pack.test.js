'use strict';

// Packaging test: `npm pack` the package, verify the tarball contents,
// extract it, and run the kv-client bin from the extracted package —
// the `npx --package=tr-key-vault-client kv-client` path. A packaging
// mistake (missing files entry, non-executable launcher, broken
// shebang, broken relative require) fails here before it can ship.

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const execFileP = promisify(execFile);

const { startStubVault } = require('./stubvault');

const ROOT = path.join(__dirname, '..');

let dir, stub;

test.before(async function() {
	dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kvpack-'));
	stub = await startStubVault();
});

test.after(async function() {
	if (stub) {
		await stub.close();
	}
	if (dir) {
		await fs.rm(dir, { recursive: true, force: true });
	}
});

test('npm pack: contents, bin executability, run from the extracted package', async function() {
	const packed = await execFileP('npm', [ 'pack', '--pack-destination', dir ], { cwd: ROOT });
	const tarball = path.join(dir, packed.stdout.trim().split('\n').pop());
	// Tarball contains exactly what the files allowlist promises.
	const listing = (await execFileP('tar', [ '-tzf', tarball ])).stdout.split('\n');
	for (const f of [ 'package/index.js', 'package/kvclient.js', 'package/kv-client',
					  'package/README.md', 'package/LICENSE', 'package/package.json' ]) {
		assert.ok(listing.includes(f), `tarball contains ${f}`);
	}
	// No internal docs or tests leak into the package.
	assert.ok(! listing.some(function(f) {
		return /SPEC|FUTURE-NOTES|OPEN-QUESTIONS|test\//.test(f);
	}), 'no internal files in the tarball');
	// Extract and run the bin from the extracted package (dependency
	// resolution via the repo's node_modules, so the test is
	// offline).
	await execFileP('tar', [ '-xzf', tarball, '-C', dir ]);
	const pkgDir = path.join(dir, 'package');
	const st = await fs.stat(path.join(pkgDir, 'kv-client'));
	assert.ok(st.mode & 0o100, 'kv-client is executable');
	const env = Object.assign({}, process.env, {
		NODE_PATH: path.join(ROOT, 'node_modules'),
		KV_CLIENT_OPT_URL: stub.url,
		KV_CLIENT_OPT_USER: stub.user,
		KV_CLIENT_OPT_TOKEN: stub.token
	});
	const r = await execFileP('node', [ path.join(pkgDir, 'kv-client'),
										'healthcheck', '--compact-json' ],
							  { cwd: dir, env });
	assert.equal(r.stdout.trim(), '{"uptime":42}');
});
