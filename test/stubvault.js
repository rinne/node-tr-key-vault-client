'use strict';

// Stub vault for the test suite: a small in-process HTTP(S) server
// speaking the tr-key-vault envelope. It fakes deterministic
// responses per request name (plus scripted misbehavior for the
// error-path tests) — this repo tests the client, not the vault.

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');

const USER = '11111111-2222-4333-8444-555555555555';
const TOKEN = '99999999-8888-4777-8666-555555555555';
const FIXED_KID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

function startStubVault(options) {
	const opts = Object.assign({}, options || {});
	const state = { ready: true, last: null };

	function respond(res, status, obj) {
		const body = Buffer.from(JSON.stringify(obj), 'utf8');
		res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8',
								'Content-Length': body.length });
		res.end(body);
	}

	function handleApi(req, res, raw) {
		let envelope;
		try {
			envelope = JSON.parse(raw);
		} catch (_) {
			return respond(res, 400, { status: 'error', errorCode: 1000, message: 'Malformed request' });
		}
		state.last = envelope;
		const op = envelope.op;
		const auth = /^Bearer (.*)$/.exec(req.headers['authorization'] || '');
		if (! (auth && (auth[1] === TOKEN) && (envelope.user === USER))) {
			return respond(res, 403, { status: 'error', op, errorCode: 1001, message: 'Unauthorized' });
		}
		const ok = function(data) { respond(res, 200, { status: 'ok', op, data }); };
		const err = function(code, message) {
			respond(res, 200, { status: 'error', op, errorCode: code, message });
		};
		const data = envelope.data || {};
		const m = /^err-(\d+)$/.exec(envelope.request);
		if (m) {
			return err(Number.parseInt(m[1]), 'Stub error');
		}
		switch (envelope.request) {
		case 'healthcheck':
			return ok({ uptime: 42 });
		case 'echo':
			return ok({ echo: data });
		case 'generate-key': {
			const kid = FIXED_KID;
			const rv = { kid };
			if (data.returnPublicKey) {
				rv.key = { kty: 'EC', crv: 'P-256', x: 'xx', y: 'yy', alg: data.alg, kid };
			}
			return ok(rv);
		}
		case 'public-key':
			return ok({ key: { kty: 'EC', crv: 'P-256', x: 'xx', y: 'yy', kid: data.kid } });
		case 'create-jwt':
			return ok({ token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwaXBlIn0.c2ln' });
		case 'verify-jwt':
			return ok({ header: { alg: 'HS256', kid: FIXED_KID }, data: { sub: 'pipe' } });
		case 'create-jwe':
			return ok({ token: 'eyJhbGciOiJBMjU2R0NNS1cifQ.a.b.c.d' });
		case 'decrypt-jwe':
			return ok({ header: { alg: 'A256GCMKW', kid: FIXED_KID }, data: { secret: 42 } });
		case 'revoke-key':
			return ok({ kid: data.kid, revoked: true });
		case 'export-key':
			return ok({ key: { kty: 'oct', k: 'QUFBQQ', alg: 'A256GCM', kid: data.kid } });
		case 'list-keys':
			return ok({ keys: [ { kid: FIXED_KID, kty: 'oct', alg: 'A256GCM' } ] });
		// --- scripted misbehavior for error-path tests ---
		case 'slow':
			setTimeout(function() { ok({}); }, (data.delayMs ?? 3000));
			return;
		case 'no-op-echo':
			return respond(res, 200, { status: 'ok', op: crypto.randomUUID(), data: {} });
		case 'missing-op':
			return respond(res, 200, { status: 'ok', data: {} });
		case 'bad-json':
			res.writeHead(200, { 'Content-Type': 'application/json' });
			return res.end('this is not json');
		case 'not-envelope':
			return respond(res, 200, { foo: 1 });
		case 'data-not-object':
			return respond(res, 200, { status: 'ok', op, data: 42 });
		case 'error-at-500':
			return respond(res, 500, { status: 'error', op, errorCode: 1900, message: 'Internal error' });
		case 'malformed-error':
			return respond(res, 200, { status: 'error', op, message: 'no code' });
		default:
			return err(1002, 'Unknown operation');
		}
	}

	function handler(req, res) {
		const pathname = new URL(req.url, 'http://localhost').pathname;
		if ((req.method === 'GET') && (pathname === '/healthz')) {
			return respond(res, 200, { status: 'ok' });
		}
		if ((req.method === 'GET') && (pathname === '/readyz')) {
			return (state.ready ?
					respond(res, 200, { status: 'ok' }) :
					respond(res, 503, { status: 'error', errorCode: 1900, message: 'Database not available' }));
		}
		if ((req.method === 'POST') && (pathname === '/api/v1')) {
			const chunks = [];
			req.on('data', function(c) { chunks.push(c); });
			req.on('end', function() { handleApi(req, res, Buffer.concat(chunks).toString('utf8')); });
			return;
		}
		return respond(res, 404, { status: 'error', errorCode: 1004, message: 'Unknown endpoint' });
	}

	const server = (opts.tls ? https.createServer(opts.tls, handler) : http.createServer(handler));

	return new Promise(function(resolve, reject) {
		server.on('error', reject);
		server.listen(0, '127.0.0.1', function() {
			const url = `${opts.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}`;
			resolve({
				server,
				url,
				user: USER,
				token: TOKEN,
				fixedKid: FIXED_KID,
				last: function() { return state.last; },
				setReady: function(v) { state.ready = !! v; },
				close: function() {
					return new Promise(function(r) { server.close(r); });
				}
			});
		});
	});
}

module.exports = { startStubVault, USER, TOKEN, FIXED_KID };
