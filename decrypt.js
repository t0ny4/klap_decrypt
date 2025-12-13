/* SPDX-License-Identifier: 0BSD */

/**
	Decrypt TAPO 'KLAP' protocol communications saved as wireshark packet dissection json:
		File | Export Packet Dissections | As JSON...

	Tested with:
	[Tapo P110 Firmware: 1.3.1 Build 240621 Rel.162048] <--> [TP-Link Tapo Android app v3.13.512]
	Captured with Wireshark 4.0.17
*/

import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, createDecipheriv } from 'node:crypto';


if (process.argv.length < 3) {
	console.log('Usage: ' + path.basename(process.argv[1]) + ' <filename>');
	process.exit();
}

const cred_file = './.credentials.js';
let cred_module = null;
try {
	await fs.access(cred_file, fs.constants.F_OK | fs.constants.R_OK);
	console.log(' * Loading credentials from', cred_file);
	cred_module = await import(cred_file);
} catch { console.log(' * Credentials file not found:', cred_file); }

const credentials = cred_module ? cred_module.credentials : [];

// for debugging
const SAVE_FILTERED = false;

const filename = process.argv[2];
const auth = {};

const fd = path.parse(filename);
const filterFilename = fd.dir + path.sep + fd.name + '.filtered' + fd.ext;
const decryptFilename = fd.dir + path.sep + fd.name + '.decrypted' + fd.ext;

const dissections = await read_dissections(filename);
console.log(` * Loaded ${dissections.length} dissections`);

console.log(' * Filtering data ...');
const filtered = filter(dissections);
if (SAVE_FILTERED) {
	await write_filtered(filtered, filterFilename);
}

console.log(' * Checking filtered data ...');
check(filtered);

console.log(' * Decrypting ...');
const decrypted = parse(filtered, credentials);

if (decrypted === false) {
	console.log(' * No decrypted results to save');
} else {
	await write_results(decrypted, decryptFilename);
}

console.log(' * Done!');
process.exit();


// ---------------------------------------------

/**
 * @param {*} filtered
 * @param {String[][]} credentials
 * @returns {String|False}
 */
function parse(filtered, credentials) {

	const device_default_creds = [
		['test@tp-link.net', 'test'],
		['kasa@tp-link.net', 'kasaSetup'],
	];

	auth.hashes = [];

	[...credentials, ...device_default_creds].forEach((cred) => {
		auth.hashes.push([cred[0], sha256(Buffer.concat([sha1(cred[0]), sha1(cred[1])]))]);
	});

	let got_auth = false;

	let output = '';
	let skipped = 0;
	let count = 0;

	for (const stream_id of Object.keys(filtered)) {

		const stream = filtered[stream_id];

		for (const frame_id of Object.keys(stream.frames)) {

			const frame = stream.frames[frame_id];
			const id = `[Stream:${stream_id} Frame:${frame_id}]`;

			if (!frame.is_http_request) {
				continue;
			}

			switch (frame.type) {

				case 'handshake1':
					// console.log('HANDSHAKE1', id);
					got_auth = handshake1(stream, frame, auth);
				break;

				case 'handshake2':
					// console.log('HANDSHAKE2', id);
					// @TODO: verify clientProof and check for HTTP200 response from server
				break;

				case 'request':
					// console.log('REQUEST', id);
					count++;

					if (!got_auth) {
						skipped++;
						continue;
					}
					// block scope due to variable declaration
					{
						const data = request(filtered, stream_id, frame_id, auth);

						if (data === false) {
							continue;
						}

						if (output === '') {
							output += '[\n' + data;
						} else {
							output += ',\n\n' + data;
						}
					}
				break;

				case '':
					console.error('[ERROR] empty type', id);
				break;

				default:
					console.error('[ERROR] unknown type:', frame.type, id);
				break;
			}
		}
	}

	if (skipped > 0) {
		console.log(`[WARNING] Skipped ${skipped} of ${count} requests due to no credentials`);
	}

	if (output === '') {
		return false;
	}

	output += '\n]\n';
	return output;
}


/**
 * @returns {String}
 */
function request(streams, stream_id, frame_id, auth) {

	const id = `Stream: ${stream_id} Frame: ${frame_id}`;
	const stream = streams[stream_id];
	const frame = stream.frames[frame_id];

	const requestPayload = decode_payload(frame.payload);

	const request = decrypt(requestPayload, frame.seq, auth);

	if (request === false) {
		console.error('[ERROR] Failed to decrypt request', id);
		return false;
	}

	if (request.substring(0, 23) === '{"method":"set_qs_info"') {
		parse_qs_info(request);
	}

	if (frame.resp_in === false) {
		console.error('[WARNING] request has no response', id);
		return request;
	}

	const respFrame = stream.frames[frame.resp_in];
	const responsePayload = decode_payload(respFrame.payload);

	const response = decrypt(responsePayload, frame.seq, auth);

	if (response === false) {
		console.error('[ERROR] Failed to decrypt response', id);
		return false;
	}

	return request + ',\n' + response;
}


function parse_qs_info(request) {

	try {
		const obj = JSON.parse(request);

		const username_b64 = obj.params.account.username ?? null;
		const password_b64 = obj.params.account.password ?? null;

		if (username_b64 === null || password_b64 === null) {
			return;
		}

		const username = Buffer.from(username_b64, 'base64').toString();
		const password = Buffer.from(password_b64, 'base64').toString();

		auth.hashes.push([username, sha256(Buffer.concat([sha1(username), sha1(password)]))]);

		console.log(' * Discovered credentials for username', username);

	} catch (err) {
		console.error('[ERROR] failed to parse set_qs_info', err);
		return;
	}
}


function handshake1(stream, frame, auth) {

	console.log(' * Found handshake1, checking for valid credentials');

	const clientNonce = decode_payload(frame.payload);

	if (clientNonce.length !== 16) {
		console.error(`[ERROR] Invalid length for clientNonce: ${clientNonce.length}`);
		return false;
	}

	if (frame.resp_in === false) {
		console.error('[ERROR] Handshake1 packet has no response');
		return false;
	}

	const resp = stream.frames[frame.resp_in];

	const serverData = decode_payload(resp.payload);

	if (serverData.length !== 48) {
		console.error(`[ERROR] Invalid length for serverData: ${serverData.length}`);
		return false;
	}

	const serverNonce = serverData.subarray(0, 16);
	const serverProof = serverData.subarray(16);

	let found_hash = false;
	let base;

	for (const hash of auth.hashes) {
		base = Buffer.concat([clientNonce, serverNonce, hash[1]]);
		const verifyHash = sha256(base);
		if (serverProof.equals(verifyHash)) {
			console.log(' * Valid credentials found for username', hash[0]);
			found_hash = true;
			break;
		}
	}

	if (found_hash !== true) {
		console.error('[ERROR] none of the available credentials are correct for this handshake');
		return false;
	}

	auth.key = sha256(Buffer.concat([text2Buffer('lsk'), base])).subarray(0, 16);
	const iv = sha256(Buffer.concat([text2Buffer('iv'), base]));
	auth.iv = Buffer.alloc(12); // 96 bits + 32 bits from seq = 128 bits
	iv.copy(auth.iv, 0, 0, 12);
	const sig = sha256(Buffer.concat([text2Buffer('ldk'), base]));
	auth.sig = Buffer.alloc(28);
	sig.copy(auth.sig, 0, 0, 28);

	return true;
}


/**
 * @param {Buffer} data
 * @param {Number} seq
 * @param {Object} auth
 * @returns {String|false}
 */
function decrypt(data, seq, auth) {

	if (data.length < 32) {
		console.error(`[ERROR] decrypt: Not enough data (${data.length} bytes)`);
		return false;
	}
	const seqBuf = Buffer.alloc(4);
	seqBuf.writeUInt32BE(seq);

	const signature = data.subarray(0, 32);
	const ciphertext = data.subarray(32);

	const checkSignature = sha256(Buffer.concat([auth.sig, seqBuf, ciphertext]));

	if (!signature.equals(checkSignature)) {
		console.error('[ERROR] decrypt: Invalid signature');
		return false;
	}

	const ivAndSeq = Buffer.concat([auth.iv, seqBuf]);
	const cipher = createDecipheriv('aes-128-cbc', auth.key, ivAndSeq);

	let plaintext = cipher.update(ciphertext);
	plaintext = Buffer.concat([plaintext, cipher.final()]);

	return plaintext.toString();
}


/**
 * Filter the Wireshark dissections, extracting just the information needed
 * @param {Array} dissections
 * @returns
 */
function filter(dissections) {

	const urlRegExp = /.*?\/app\/(handshake(?:1|2)|request)(?:\?seq=(\d+)|)/;

	const result = {};

	let idx = 0;

	dissections.forEach((packet) => {

		idx++;

		let id = `[Entry: ${idx}]`;

		const source = packet._source || null;
		if (source === null) {
			console.error('[ERROR] No source property', id);
			return;
		}

		const layers = source.layers || null;
		if (layers === null) {
			console.error('[ERROR] No layers property', id);
			return;
		}

		const frame_layer = layers.frame || null;
		if (frame_layer === null) {
			console.error('[ERROR] No frame layer property', id);
			return;
		}

		const frame_num = getInt(frame_layer['frame.number']);
		if (frame_num === false) {
			console.error('[ERROR] Invalid frame number', frame_layer['frame.number'], id);
			return;
		}
		id = `[Frame: ${frame_num}]`;

		const ip_layer = layers.ip || null;
		if (ip_layer === null) {
			console.error('[ERROR] No ip layer property', id);
			return;
		}

		const tcp_layer = layers.tcp || null;
		if (tcp_layer === null) {
			console.error('[ERROR] No tcp layer property', id);
			return;
		}

		const tcp_stream = getInt(tcp_layer['tcp.stream']);
		if (tcp_stream === false) {
			console.error('[ERROR] Invalid stream number', tcp_layer['tcp.stream'], id);
			return;
		}
		id = `[Stream: ${tcp_stream} Frame: ${frame_num}]`;

		const tcp_segments = layers['tcp.segments'] || null;

		const http_layer = layers.http || null;
		if (http_layer === null) {
			console.error('[ERROR] No http layer property', id);
			return;
		}

		if (result[tcp_stream] === undefined) {
			result[tcp_stream] = {};
			result[tcp_stream].srcIP = ip_layer['ip.src'] || '';
			result[tcp_stream].srcPort = getInt(tcp_layer['tcp.srcport']);
			result[tcp_stream].destIP = ip_layer['ip.dst'] || '';
			result[tcp_stream].destPort = getInt(tcp_layer['tcp.dstport']);
			result[tcp_stream].frames = {};
		}

		const details = {};

		details.content_length = getInt(http_layer['http.content_length_header']);

		if (details.content_length === false) {
			console.error('[WARNING] No http.content_length_header (assuming 0)', id);
			details.content_length = 0;
		}

		/** @type {String} */
		let tcp_payload;

		if (tcp_segments !== null) {
			tcp_payload = tcp_segments['tcp.reassembled.data'] || '';
		} else {
			tcp_payload = tcp_layer['tcp.payload'] || '';
		}

		// keep just the http body part of the payload (3 characters per byte e.g. ":FF")
		let offset = tcp_payload.length - (details.content_length * 3);
		if (offset < 0) {
			console.warn(
				'[WARNING] payload appears too small for http body',
				id, details.content_length * 3, tcp_payload.length
			);
			offset = 0;
		}
		details.payload = tcp_payload.substring(offset);

		if (http_layer['http.request_number'] !== undefined) {

			details.is_http_request = true;

			details.resp_in = getInt(http_layer['http.response_in']);

			if (details.resp_in === false) {
				console.error('[WARNING] Request has no reply', id);
			}

			/** @type {String} */
			const uri = http_layer['http.request.full_uri'] || '';

			const res = uri.match(urlRegExp);

			if (res === null) {
				console.error('[ERROR] Failed to parse uri', uri, id);
				return;
			}

			details.type = res[1];
			details.seq = getInt(res[2]);

			if (details.seq === false) {
				// perfectly valid for handshake packets to not have a seq
				details.seq = 0;
			}

		} else {
			details.is_http_request = false;
		}

		result[tcp_stream].frames[frame_num] = details;
	});

	return result;
}


/**
 * Check for unused frames
 * @param {Object} filtered
 */
function check(filtered) {

	for (const stream of Object.values(filtered)) {
		for (const frame of Object.values(stream.frames)) {
			if (frame.is_http_request) {
				frame.consumed = true;
				if (frame.resp_in !== false) {
					stream.frames[frame.resp_in].consumed = true;
				}
			}
		}
	}

	let error = false;
	for (const stream_id of Object.keys(filtered)) {
		const stream = filtered[stream_id];
		for (const frame_id of Object.keys(stream.frames)) {
			const consumed = stream.frames[frame_id].consumed || false;
			if (consumed !== true) {
				const id = `[Stream: ${stream_id} Frame: ${frame_id}]`;
				console.error('[WARNING] Unreferenced frame', id);
				error = true;
			}
		}
	}

	return !error;
}


function getInt(input) {
	const t = typeof input;
	if (t !== 'string' && t !== 'number') {
		return false;
	}
	return parseInt(input || 0, 10);
}


function text2Buffer(text) { return Buffer.from(text, 'utf-8'); }
function sha1(data) { return createHash('sha1').update(data).digest(); }
function sha256(data) { return createHash('sha256').update(data).digest(); }


/**
 * Create a buffer from a wireshark hex string
 * @param {String} hexString
 * @returns {Buffer}
 */
function decode_payload(hexString) {
	return Buffer.from(hexString.replaceAll(':', ''), 'hex');
}


async function read_dissections(filename) {

	try {
		const fp = await fs.open(filename);
		const fileContents = await fp.readFile();
		fp.close();
		const dissections = JSON.parse(fileContents);
		if (dissections.length === undefined) {
			console.error('[ERROR] Invalid data in file (no length property)');
			process.exit();
		}
		return dissections;
	} catch (err) {
		console.error('[ERROR] Failed to load dissections: "' + filename + '"', err.message);
		process.exit();
	}
}


async function write_filtered(obj, filename) {
	console.log(' * Writing filtered data to:', filename);
	try {
		const fp = await fs.open(filename, 'w');
		const fileContents = JSON.stringify(obj, null, 2);
		await fp.writeFile(fileContents);
		fp.close();
	} catch (err) {
		console.error('[WARNING] Failed to write file:', filename, err.message);
		return false;
	}
	return true;
}


async function write_results(txt, filename) {

	console.log(' * Writing results to:', filename);
	try {
		const fp = await fs.open(filename, 'w');
		await fp.writeFile(txt);
		fp.close();
	} catch (err) {
		console.error('[WARNING] Failed to write file:', filename, err.message);
		return false;
	}
	return true;
}
