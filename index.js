'use strict';

// tr-key-vault-client — client library for the tr-key-vault server.
//
// Promise-based client for the vault's JSON-over-POST API
// (POST /api/v1 plus the GET /healthz and /readyz probes). Pure API
// client: no cryptography, no database access, no dependencies —
// node:http / node:https / node:crypto only.
//
//   const KeyVaultClient = require('tr-key-vault-client');
//   const kc = new KeyVaultClient({ url, user, token });
//   const { kid } = await kc.generateKey('ES256', { returnPublicKey: true });
//
// Errors: methods reject with typed errors exported as properties of
// the class (KeyVaultApiError, KeyVaultTransportError,
// KeyVaultProtocolError, all extending KeyVaultClientError). Local
// usage errors throw plain TypeError.

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isUuid(s) {
	return ((typeof(s) === 'string') && UUID_RE.test(s));
}

function isPlainObject(x) {
	return ((typeof(x) === 'object') && (x !== null) && ! Array.isArray(x));
}

// Common base so callers can catch all client errors broadly.
class KeyVaultClientError extends Error {
	constructor(message) {
		super(message);
		this.name = new.target.name;
	}
}

// The vault answered with a well-formed error envelope.
class KeyVaultApiError extends KeyVaultClientError {
	constructor(message, errorCode, op) {
		super(message);
		this.errorCode = errorCode;
		this.op = op;
	}
}

// Network failure, timeout, TLS failure, non-JSON response or an
// unexpected HTTP status without a clean error envelope.
class KeyVaultTransportError extends KeyVaultClientError {
	constructor(message, cause) {
		super(message);
		if (cause !== undefined) {
			this.cause = cause;
		}
	}
}

// The response violates the protocol contract (op echo mismatch,
// envelope shape violation).
class KeyVaultProtocolError extends KeyVaultClientError {
}

const CONSTRUCTOR_OPTS = [ 'url', 'user', 'token', 'timeout', 'insecure', 'ca', 'keepAlive' ];
// Per-call options handled by the client itself; everything else in a
// method options object is forwarded into the operation data.
const CALL_OPTS = [ 'op', 'timeout' ];

class KeyVaultClient {

	#url;
	#user;
	#token;
	#timeout;
	#insecure;
	#ca;
	#keepAlive;
	#httpAgent;
	#httpsAgent;

	constructor(options) {
		if (! isPlainObject(options)) {
			throw new TypeError('options must be an object');
		}
		for (const prop of Object.keys(options)) {
			if (! CONSTRUCTOR_OPTS.includes(prop)) {
				throw new TypeError(`Unknown option: ${prop}`);
			}
		}
		const { url, user, token, timeout, insecure, ca, keepAlive } = options;
		if (typeof(url) !== 'string') {
			throw new TypeError('url must be a string');
		}
		let u;
		try {
			u = new URL(url);
		} catch (_) {
			throw new TypeError('url is not a valid URL');
		}
		if (! [ 'http:', 'https:' ].includes(u.protocol)) {
			throw new TypeError('url must be http or https');
		}
		// Normalize: strip trailing slashes and an /api/v1 suffix.
		this.#url = u.toString().replace(/\/+$/, '').replace(/\/api\/v1$/, '');
		if ((user !== undefined) && ! isUuid(user)) {
			throw new TypeError('user must be an UUID string');
		}
		this.#user = ((user !== undefined) ? user.toLowerCase() : undefined);
		if ((token !== undefined) && ! isUuid(token)) {
			throw new TypeError('token must be an UUID string');
		}
		this.#token = token;
		if (timeout !== undefined) {
			if (! (Number.isSafeInteger(timeout) && (timeout >= 1))) {
				throw new TypeError('timeout must be a positive integer (seconds)');
			}
		}
		this.#timeout = (timeout ?? 30);
		if ((insecure !== undefined) && (typeof(insecure) !== 'boolean')) {
			throw new TypeError('insecure must be a boolean');
		}
		this.#insecure = !! insecure;
		if ((ca !== undefined) && ! ((typeof(ca) === 'string') || Buffer.isBuffer(ca))) {
			throw new TypeError('ca must be a string or a Buffer');
		}
		this.#ca = ca;
		if ((keepAlive !== undefined) && (typeof(keepAlive) !== 'boolean')) {
			throw new TypeError('keepAlive must be a boolean');
		}
		this.#keepAlive = (keepAlive ?? true);
		this.#httpAgent = null;
		this.#httpsAgent = null;
	}

	#agent(isHttps) {
		if (! this.#keepAlive) {
			return undefined;
		}
		if (isHttps) {
			if (! this.#httpsAgent) {
				this.#httpsAgent = new https.Agent({ keepAlive: true });
			}
			return this.#httpsAgent;
		}
		if (! this.#httpAgent) {
			this.#httpAgent = new http.Agent({ keepAlive: true });
		}
		return this.#httpAgent;
	}

	// Raw HTTP exchange. Resolves { status, body } (body as utf-8
	// text); rejects KeyVaultTransportError.
	#httpRequest(path, method, bodyObj, withAuth, timeoutSeconds) {
		return new Promise((resolve, reject) => {
			const u = new URL(this.#url + path);
			const isHttps = (u.protocol === 'https:');
			const mod = (isHttps ? https : http);
			const payload = ((bodyObj !== undefined) ?
							 Buffer.from(JSON.stringify(bodyObj), 'utf8') : null);
			const headers = {};
			if (payload) {
				headers['Content-Type'] = 'application/json';
				headers['Content-Length'] = payload.length;
			}
			if (withAuth) {
				headers['Authorization'] = `Bearer ${this.#token}`;
			}
			const reqOpts = {
				method,
				hostname: u.hostname,
				port: (u.port || (isHttps ? 443 : 80)),
				path: (u.pathname + u.search),
				headers,
				agent: this.#agent(isHttps)
			};
			if (isHttps) {
				if (this.#insecure) {
					reqOpts.rejectUnauthorized = false;
				}
				if (this.#ca !== undefined) {
					reqOpts.ca = this.#ca;
				}
			}
			const req = mod.request(reqOpts, function(res) {
				const chunks = [];
				res.on('data', function(c) { chunks.push(c); });
				res.on('end', function() {
					resolve({ status: res.statusCode,
							  body: Buffer.concat(chunks).toString('utf8') });
				});
				res.on('error', function(e) {
					reject(new KeyVaultTransportError(`response error: ${e.message}`, e));
				});
			});
			req.on('error', function(e) {
				reject(new KeyVaultTransportError(`request failed: ${e.message}`, e));
			});
			req.setTimeout(timeoutSeconds * 1000, function() {
				req.destroy(new Error('request timeout'));
			});
			if (payload) {
				req.write(payload);
			}
			req.end();
		});
	}

	// Validate a per-call options object and return
	// { op, timeout, forward } where `forward` carries the
	// method-specific properties to merge into the operation data.
	#callOpts(options) {
		if (options === undefined) {
			return { op: undefined, timeout: this.#timeout, forward: {} };
		}
		if (! isPlainObject(options)) {
			throw new TypeError('options must be an object');
		}
		if ((options.op !== undefined) && ! isUuid(options.op)) {
			throw new TypeError('options.op must be an UUID string');
		}
		if ((options.timeout !== undefined) &&
			! (Number.isSafeInteger(options.timeout) && (options.timeout >= 1))) {
			throw new TypeError('options.timeout must be a positive integer (seconds)');
		}
		const forward = {};
		for (const [ prop, value ] of Object.entries(options)) {
			if (! CALL_OPTS.includes(prop)) {
				forward[prop] = value;
			}
		}
		return { op: options.op?.toLowerCase(),
				 timeout: (options.timeout ?? this.#timeout),
				 forward };
	}

	// Send one API operation and return the parsed envelope plus the
	// op that was sent. Rejects KeyVaultTransportError /
	// KeyVaultProtocolError; API-level errors are the caller's
	// business (they see the envelope).
	async #exchange(request, data, callOpts) {
		if (! (this.#user && this.#token)) {
			throw new TypeError('user and token are required for authenticated operations');
		}
		const op = (callOpts.op || crypto.randomUUID());
		const envelope = { user: this.#user, op, request, data };
		const res = await this.#httpRequest('/api/v1', 'POST', envelope, true, callOpts.timeout);
		let body;
		try {
			body = JSON.parse(res.body);
		} catch (_) {
			throw new KeyVaultTransportError(`non-JSON response (HTTP ${res.status})`);
		}
		if (! (isPlainObject(body) && [ 'ok', 'error' ].includes(body.status))) {
			throw new KeyVaultTransportError(`unexpected response (HTTP ${res.status})`);
		}
		// The op echo, when present, must match what was sent; a
		// successful envelope must always carry it.
		if ((body.op !== undefined) && (body.op !== op)) {
			throw new KeyVaultProtocolError('response op does not match the request');
		}
		if (body.status === 'ok') {
			if ((res.status !== 200) || (body.op !== op) || ! isPlainObject(body.data)) {
				throw new KeyVaultProtocolError('malformed success envelope');
			}
		} else {
			if (! (Number.isSafeInteger(body.errorCode) && (typeof(body.message) === 'string'))) {
				throw new KeyVaultProtocolError('malformed error envelope');
			}
		}
		return { body, op };
	}

	// Send an operation, unwrap the data, reject on API errors.
	async #api(request, data, options) {
		const callOpts = this.#callOpts(options);
		const { body } = await this.#exchange(request, data, callOpts);
		if (body.status === 'error') {
			throw new KeyVaultApiError(body.message, body.errorCode, body.op);
		}
		return body.data;
	}

	// ---- probes ----

	async #probe(path, options) {
		const callOpts = this.#callOpts(options);
		const res = await this.#httpRequest(path, 'GET', undefined, false, callOpts.timeout);
		return (res.status === 200);
	}

	// Unauthenticated liveness probe. Resolves true when the vault
	// answers HTTP 200, false on any other well-formed HTTP answer.
	async healthz(options) {
		return this.#probe('/healthz', options);
	}

	// Unauthenticated readiness probe (database ping on the vault
	// side; 503 -> false).
	async readyz(options) {
		return this.#probe('/readyz', options);
	}

	// ---- API operations ----

	// Authenticated liveness (the vault `healthcheck` operation).
	// Resolves { uptime }.
	async hello(options) {
		return this.#api('healthcheck', {}, options);
	}

	// Generate a key into the vault. `alg` is mandatory and canonical
	// for the key's lifetime. options: kty, crv, keyLength, nbf, exp,
	// acl, returnPublicKey. Resolves { kid, key? }.
	async generateKey(alg, options) {
		if (! ((typeof(alg) === 'string') && alg)) {
			throw new TypeError('alg must be a non-empty string');
		}
		const callData = Object.assign({}, this.#callOpts(options).forward, { alg });
		return this.#api('generate-key', callData, options);
	}

	// Fetch the public JWK of an asymmetric key. Resolves the JWK.
	async publicKey(kid, options) {
		return this.#kidOp('public-key', kid, options).then(function(data) { return data.key; });
	}

	// Sign a JWT with a vault key. `payload` is the claims object.
	// Resolves the compact JWT string.
	async createJwt(kid, payload, options) {
		this.#requireKid(kid);
		if (! isPlainObject(payload)) {
			throw new TypeError('payload must be an object');
		}
		const callData = Object.assign({}, this.#callOpts(options).forward,
									   { kid: kid.toLowerCase(), data: payload });
		return this.#api('create-jwt', callData, options).then(function(data) { return data.token; });
	}

	// Parse and verify a JWT. options.kid selects the key when the
	// token header does not carry it. Resolves { header, data }.
	async verifyJwt(token, options) {
		this.#requireToken(token);
		const callData = Object.assign({}, this.#callOpts(options).forward, { token });
		this.#normalizeKidProp(callData);
		return this.#api('verify-jwt', callData, options);
	}

	// Encrypt a JWE with a vault key. `data` is any JSON-serializable
	// value. options.compress: false (default) | true | 'auto'.
	// Resolves the compact JWE string.
	async createJwe(kid, data, options) {
		this.#requireKid(kid);
		if (data === undefined) {
			throw new TypeError('data is required');
		}
		const callData = Object.assign({}, this.#callOpts(options).forward,
									   { kid: kid.toLowerCase(), data });
		return this.#api('create-jwe', callData, options).then(function(d) { return d.token; });
	}

	// Decrypt a JWE. options.kid as in verifyJwt. Resolves
	// { header, data }.
	async decryptJwe(token, options) {
		this.#requireToken(token);
		const callData = Object.assign({}, this.#callOpts(options).forward, { token });
		this.#normalizeKidProp(callData);
		return this.#api('decrypt-jwe', callData, options);
	}

	// Hard-delete a key. Resolves undefined.
	async revokeKey(kid, options) {
		await this.#kidOp('revoke-key', kid, options);
	}

	// Export the secret material of a key (server must allow exports;
	// caller needs the export-secret-key class). Resolves the full
	// JWK.
	async exportKey(kid, options) {
		return this.#kidOp('export-key', kid, options).then(function(data) { return data.key; });
	}

	// List the keys the caller holds at least one ACL class on.
	// Resolves [ { kid, kty, alg }, ... ].
	async listKeys(options) {
		return this.#api('list-keys', {}, options).then(function(data) { return data.keys; });
	}

	// Escape hatch: send an arbitrary request name with caller-
	// supplied data. Resolves the FULL response envelope — including
	// error envelopes (API-level errors do not reject here); rejects
	// only on transport/protocol errors.
	async raw(request, data, options) {
		if (! ((typeof(request) === 'string') && request)) {
			throw new TypeError('request must be a non-empty string');
		}
		if (data === undefined) {
			data = {};
		}
		const callOpts = this.#callOpts(options);
		const { body } = await this.#exchange(request, data, callOpts);
		return body;
	}

	// ---- internal helpers ----

	#requireKid(kid) {
		if (! isUuid(kid)) {
			throw new TypeError('kid must be an UUID string');
		}
	}

	#requireToken(token) {
		if (! ((typeof(token) === 'string') && token)) {
			throw new TypeError('token must be a non-empty string');
		}
	}

	#normalizeKidProp(callData) {
		if (callData.kid !== undefined) {
			if (! isUuid(callData.kid)) {
				throw new TypeError('options.kid must be an UUID string');
			}
			callData.kid = callData.kid.toLowerCase();
		}
	}

	async #kidOp(request, kid, options) {
		this.#requireKid(kid);
		const callData = Object.assign({}, this.#callOpts(options).forward,
									   { kid: kid.toLowerCase() });
		return this.#api(request, callData, options);
	}

}

KeyVaultClient.KeyVaultClientError = KeyVaultClientError;
KeyVaultClient.KeyVaultApiError = KeyVaultApiError;
KeyVaultClient.KeyVaultTransportError = KeyVaultTransportError;
KeyVaultClient.KeyVaultProtocolError = KeyVaultProtocolError;

module.exports = KeyVaultClient;
