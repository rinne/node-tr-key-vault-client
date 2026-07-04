'use strict';

// kv-client: a thin command-line client for the tr-key-vault API,
// built on the KeyVaultClient library (KV-CLIENT-SPEC.md). It builds
// the request from options/arguments, calls the vault, and prints the
// response. No cryptography, no database access.
//
// Usage: kv-client [global-options] <command> [command-options] [args]
//
// Exit codes: 0 ok, 1 local/usage error, 2 transport/protocol error,
//             3 API operation error.

module.exports = async function() {

	const name = 'kv-client';
	const NAME = 'KV_CLIENT';

	const crypto = require('node:crypto');
	const fs = require('node:fs');

	const Optist = require('optist');
	const ou = require('optist/util');

	const KeyVaultClient = require('./index');
	const { KeyVaultApiError, KeyVaultTransportError, KeyVaultProtocolError } = KeyVaultClient;

	const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	const isUuid = function(s) { return ((typeof(s) === 'string') && UUID_RE.test(s)); };
	const isPlainObject = function(x) {
		return ((typeof(x) === 'object') && (x !== null) && ! Array.isArray(x));
	};

	// Local/usage error -> exit 1.
	function usageError(msg) {
		process.stderr.write(`${name}: ${msg}\n`);
		process.exit(1);
	}
	// Transport/protocol error -> exit 2.
	function transportError(msg) {
		process.stderr.write(`${name}: ${msg}\n`);
		process.exit(2);
	}

	const uuidCb = function(s) { return (isUuid(s) ? s.toLowerCase() : undefined); };
	const compressCb = function(s) {
		return ([ 'false', 'true', 'auto' ].includes(s) ? s : undefined);
	};

	// Command-first invocation: kv-client <command> [options]. A
	// positional argument (raw's request name, verify/decrypt's token
	// or '-') must come either directly after the command or after
	// all the options; a leading one — including a bare '-' — is
	// lifted off argv here because optist stops option parsing at the
	// first non-option token.
	const av = process.argv.slice(2);
	const command = ((av.length > 0) && ! av[0].startsWith('-')) ? av.shift() : undefined;
	const leadingArg = ((av.length > 0) && ((av[0] === '-') || ! av[0].startsWith('-'))) ?
		  av.shift() : undefined;

	const opt = ((new Optist())
				 .opts([
					 // --- connection / auth ---
					 { longName: 'url',
					   description: 'Base URL of the vault, e.g. https://vault.example.com',
					   hasArg: true,
					   environment: NAME + '_OPT_URL' },
					 { longName: 'user',
					   description: 'Caller user id (UUID)',
					   hasArg: true,
					   optArgCb: uuidCb,
					   environment: NAME + '_OPT_USER' },
					 { longName: 'token',
					   description: 'Bearer token (UUID). Prefer the environment or --token-file (argv is visible in ps)',
					   hasArg: true,
					   environment: NAME + '_OPT_TOKEN' },
					 { longName: 'token-file',
					   description: 'Read the bearer token from a file',
					   hasArg: true,
					   conflictsWith: [ 'token' ],
					   environment: NAME + '_OPT_TOKEN_FILE' },
					 { longName: 'op',
					   description: 'Client operation correlation id (UUID); default a fresh random one',
					   hasArg: true,
					   optArgCb: uuidCb },
					 { longName: 'timeout',
					   description: 'Request timeout in seconds',
					   hasArg: true,
					   defaultValue: '30',
					   optArgCb: ou.integerWithLimitsCbFactory(1, 3600),
					   environment: NAME + '_OPT_TIMEOUT' },
					 { shortName: 'k', longName: 'insecure',
					   description: 'Skip TLS certificate verification (test only)',
					   environment: NAME + '_OPT_INSECURE' },
					 { longName: 'ca-file',
					   description: 'PEM CA bundle to trust',
					   hasArg: true,
					   environment: NAME + '_OPT_CA_FILE' },
					 // --- output ---
					 { longName: 'compact-json',
					   description: 'Emit compact single-line JSON (default is pretty-printed)' },
					 { longName: 'raw',
					   description: 'Print the full response envelope instead of just data' },
					 { longName: 'field',
					   description: 'Print only this field of the result (scalar bare, object/array as JSON)',
					   hasArg: true },
					 { shortName: 'v', longName: 'verbose',
					   description: 'Log the request to stderr' },
					 // --- operation data ---
					 { longName: 'alg', description: 'Key algorithm (generate-key)', hasArg: true },
					 { longName: 'kty', description: 'Key type (generate-key)', hasArg: true },
					 { longName: 'crv', description: 'EC curve (generate-key)', hasArg: true },
					 { longName: 'key-length',
					   description: 'Key length / RSA modulus bits (generate-key)',
					   hasArg: true,
					   optArgCb: ou.integerWithLimitsCbFactory(1, 16384) },
					 { longName: 'nbf',
					   description: 'Key not-before, unix timestamp (generate-key)',
					   hasArg: true,
					   optArgCb: ou.integerWithLimitsCbFactory(1, 253402300799) },
					 { longName: 'exp',
					   description: 'Key expiry, unix timestamp (generate-key)',
					   hasArg: true,
					   optArgCb: ou.integerWithLimitsCbFactory(1, 253402300799) },
					 { longName: 'return-public-key',
					   description: 'Return the public key (generate-key, asymmetric)' },
					 { longName: 'acl',
					   description: 'ACL as a JSON object (generate-key)',
					   hasArg: true },
					 { longName: 'acl-file',
					   description: 'Read the ACL JSON object from a file (generate-key)',
					   hasArg: true,
					   conflictsWith: [ 'acl' ] },
					 { longName: 'kid',
					   description: 'Target key id (UUID)',
					   hasArg: true,
					   optArgCb: uuidCb },
					 { longName: 'data',
					   description: 'Operation payload as JSON (- reads stdin)',
					   hasArg: true },
					 { longName: 'data-file',
					   description: 'Read the operation payload JSON from a file',
					   hasArg: true,
					   conflictsWith: [ 'data' ] },
					 { longName: 'compress',
					   description: 'JWE compression: false | true | auto (create-jwe)',
					   hasArg: true,
					   optArgCb: compressCb }
				 ])
				 .help(name)
				 .parse(av, 0, 1));

	if (! command) {
		usageError('no command given (try --help)');
	}

	const verbose = opt.value('verbose');

	// ---- input helpers ----

	// stdin is read asynchronously (a shell pipe puts fd 0 in
	// non-blocking mode, so a synchronous read can throw EAGAIN). It
	// is consumed up front, once, into `stdinData` when the selected
	// command actually needs it.
	let stdinData;

	async function readAllStdin() {
		if (process.stdin.isTTY) {
			usageError('expected input on stdin');
		}
		const chunks = [];
		try {
			for await (const c of process.stdin) {
				chunks.push(c);
			}
		} catch (e) {
			usageError(`cannot read stdin: ${e.message}`);
		}
		return Buffer.concat(chunks).toString('utf8');
	}

	function readStdin() {
		return stdinData;
	}

	function payloadInput() {
		let text;
		if (opt.value('data') !== undefined) {
			text = (opt.value('data') === '-') ? readStdin() : opt.value('data');
		} else if (opt.value('data-file') !== undefined) {
			try {
				text = fs.readFileSync(opt.value('data-file'), 'utf8');
			} catch (e) {
				usageError(`cannot read --data-file: ${e.message}`);
			}
		} else {
			return undefined;
		}
		try {
			return JSON.parse(text);
		} catch (_) {
			usageError('payload is not valid JSON');
		}
	}

	function requirePayload() {
		const p = payloadInput();
		if (p === undefined) {
			usageError('this command requires --data / --data-file / --data -');
		}
		return p;
	}

	function aclInput() {
		let text;
		if (opt.value('acl') !== undefined) {
			text = opt.value('acl');
		} else if (opt.value('acl-file') !== undefined) {
			try {
				text = fs.readFileSync(opt.value('acl-file'), 'utf8');
			} catch (e) {
				usageError(`cannot read --acl-file: ${e.message}`);
			}
		} else {
			return undefined;
		}
		let v;
		try {
			v = JSON.parse(text);
		} catch (_) {
			usageError('acl is not valid JSON');
		}
		if (! isPlainObject(v)) {
			usageError('acl must be a JSON object');
		}
		return v;
	}

	// The compact JOSE token for verify/decrypt: positional argument
	// (before or after the options), or stdin (explicit '-' or no
	// positional).
	function positionalArg() {
		return (leadingArg ?? opt.rest()[0]);
	}

	function tokenInput() {
		const pos = positionalArg();
		if ((pos !== undefined) && (pos !== '-')) {
			return pos;
		}
		return readStdin().trim();
	}

	function requireKid() {
		const kid = opt.value('kid');
		if (! kid) {
			usageError('this command requires --kid <uuid>');
		}
		return kid;
	}

	// Consume stdin once, up front, if this command will read it.
	{
		const dataIsStdin = (opt.value('data') === '-');
		const tokenFromStdin = ([ 'verify-jwt', 'decrypt-jwe' ].includes(command) &&
								((positionalArg() === undefined) || (positionalArg() === '-')));
		if (dataIsStdin || tokenFromStdin) {
			stdinData = await readAllStdin();
		}
	}

	// ---- command dispatch: build the request plan ----

	let plan;
	switch (command) {
	case 'healthz':
	case 'readyz':
		plan = { probe: command };
		break;
	case 'healthcheck':
		plan = { request: 'healthcheck', data: {} };
		break;
	case 'generate-key': {
		if (! opt.value('alg')) {
			usageError('generate-key requires --alg');
		}
		const data = { alg: opt.value('alg') };
		if (opt.value('kty') !== undefined) { data.kty = opt.value('kty'); }
		if (opt.value('crv') !== undefined) { data.crv = opt.value('crv'); }
		if (opt.value('key-length') !== undefined) { data.keyLength = opt.value('key-length'); }
		if (opt.value('nbf') !== undefined) { data.nbf = opt.value('nbf'); }
		if (opt.value('exp') !== undefined) { data.exp = opt.value('exp'); }
		const acl = aclInput();
		if (acl !== undefined) { data.acl = acl; }
		if (opt.value('return-public-key')) { data.returnPublicKey = true; }
		plan = { request: 'generate-key', data };
		break;
	}
	case 'public-key':
		plan = { request: 'public-key', data: { kid: requireKid() } };
		break;
	case 'create-jwt':
		plan = { request: 'create-jwt', data: { kid: requireKid(), data: requirePayload() } };
		break;
	case 'verify-jwt': {
		const data = { token: tokenInput() };
		if (opt.value('kid')) { data.kid = opt.value('kid'); }
		plan = { request: 'verify-jwt', data };
		break;
	}
	case 'create-jwe': {
		const data = { kid: requireKid(), data: requirePayload() };
		if (opt.value('compress') !== undefined) {
			const c = opt.value('compress');
			data.compress = ((c === 'auto') ? 'auto' : (c === 'true'));
		}
		plan = { request: 'create-jwe', data };
		break;
	}
	case 'decrypt-jwe': {
		const data = { token: tokenInput() };
		if (opt.value('kid')) { data.kid = opt.value('kid'); }
		plan = { request: 'decrypt-jwe', data };
		break;
	}
	case 'revoke-key':
		plan = { request: 'revoke-key', data: { kid: requireKid() } };
		break;
	case 'export-key':
		plan = { request: 'export-key', data: { kid: requireKid() } };
		break;
	case 'list-keys':
		plan = { request: 'list-keys', data: {} };
		break;
	case 'raw': {
		const reqName = positionalArg();
		if (! reqName) {
			usageError('raw requires a request name argument');
		}
		const data = payloadInput();
		plan = { request: reqName, data: ((data === undefined) ? {} : data) };
		break;
	}
	default:
		usageError(`unknown command: ${command}`);
	}

	// ---- client construction ----

	if (! opt.value('url')) {
		usageError('--url is required (or set ' + NAME + '_OPT_URL)');
	}
	let authToken = opt.value('token');
	if ((authToken === undefined) && (opt.value('token-file') !== undefined)) {
		try {
			authToken = fs.readFileSync(opt.value('token-file'), 'utf8').trim();
		} catch (e) {
			usageError(`cannot read --token-file: ${e.message}`);
		}
	}
	let ca;
	if (opt.value('ca-file')) {
		try {
			ca = fs.readFileSync(opt.value('ca-file'));
		} catch (e) {
			usageError(`cannot read --ca-file: ${e.message}`);
		}
	}
	if (plan.request) {
		if (! opt.value('user')) {
			usageError('--user is required (or set ' + NAME + '_OPT_USER)');
		}
		if (! authToken) {
			usageError('a bearer token is required (--token, --token-file or ' + NAME + '_OPT_TOKEN)');
		}
	}

	const clientOpts = { url: opt.value('url'), timeout: opt.value('timeout') };
	if (opt.value('user')) { clientOpts.user = opt.value('user'); }
	if (authToken) { clientOpts.token = authToken; }
	if (opt.value('insecure')) { clientOpts.insecure = true; }
	if (ca !== undefined) { clientOpts.ca = ca; }
	// The CLI is a one-shot process; keep-alive would only hold
	// sockets it never reuses.
	clientOpts.keepAlive = false;

	let kc;
	try {
		kc = new KeyVaultClient(clientOpts);
	} catch (e) {
		usageError(e.message);
	}

	// ---- output ----

	function toJson(v) {
		return (opt.value('compact-json') ? JSON.stringify(v) : JSON.stringify(v, null, 2));
	}

	function printResult(outputObj, envelope) {
		if (opt.value('raw')) {
			process.stdout.write(toJson(envelope) + '\n');
			return;
		}
		if (opt.value('field') !== undefined) {
			const f = opt.value('field');
			if (! (isPlainObject(outputObj) && (f in outputObj))) {
				usageError(`field not present in result: ${f}`);
			}
			const val = outputObj[f];
			if ((typeof(val) === 'object') && (val !== null)) {
				process.stdout.write(toJson(val) + '\n');
			} else {
				process.stdout.write(String(val) + '\n');
			}
			return;
		}
		process.stdout.write(toJson(outputObj) + '\n');
	}

	// ---- run ----

	if (verbose) {
		process.stderr.write(`${name}: ${plan.probe ? ('GET /' + plan.probe) : ('POST /api/v1 ' + plan.request)} @ ${opt.value('url')}\n`);
	}

	try {
		if (plan.probe) {
			const up = ((plan.probe === 'healthz') ? await kc.healthz() : await kc.readyz());
			if (! up) {
				process.stderr.write(`${name}: /${plan.probe} not ok\n`);
				process.exit(2);
			}
			printResult({ status: 'ok' }, { status: 'ok' });
			process.exit(0);
		}
		const envelope = await kc.raw(plan.request, plan.data,
									  { op: (opt.value('op') || crypto.randomUUID()) });
		if (envelope.status === 'error') {
			process.stderr.write(`${name}: API error ${envelope.errorCode}: ${envelope.message}\n`);
			if (opt.value('raw')) {
				process.stdout.write(toJson(envelope) + '\n');
			}
			process.exit(3);
		}
		printResult(envelope.data, envelope);
		process.exit(0);
	} catch (e) {
		if ((e instanceof KeyVaultTransportError) || (e instanceof KeyVaultProtocolError)) {
			transportError(e.message);
		}
		if (e instanceof KeyVaultApiError) {
			// raw() does not reject on API errors; belt and braces.
			process.stderr.write(`${name}: API error ${e.errorCode}: ${e.message}\n`);
			process.exit(3);
		}
		usageError(e.message);
	}

};
