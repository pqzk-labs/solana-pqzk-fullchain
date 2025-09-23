// Crypto utilities for the CLI chat: SLH-DSA 128s (WASM), Kyber768 KEM via local CLI, AES-256-GCM.

import { promisify } from 'node:util';
import { execFile as _execFile } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

// SLH-DSA via wasm-pack build under crates/slh-dsa-wasm/pkg
import {
  generate_keypair,
  sign   as wasm_sign,
  verify as wasm_verify,
  vk_bytes_from_sk as wasm_vk_bytes,
} from '../../../../crates/slh-dsa-wasm/pkg/slh_dsa_wasm/slh_dsa_wasm.js';

export const PARAM = 'sha2_128s';

// Base64 helpers reused by other files
export const u8ToB64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
export const b64ToU8 = (b: string) => Uint8Array.from(Buffer.from(b, 'base64'));

// SLH-DSA keypair as base64 strings
export function slhKeygen() {
  const { public_key, private_key } = generate_keypair();
  return {
    param: PARAM,
    pkB64: u8ToB64(public_key),
    skB64: u8ToB64(private_key),
  };
}

// Derive verifying key bytes from base64 secret key
export function deriveVkFromSk(skB64: string): Uint8Array {
  return Uint8Array.from(wasm_vk_bytes(b64ToU8(skB64)));
}

// Re-exports for convenience
export const slhSign   = wasm_sign;
export const slhVerify = wasm_verify;

// AES-256-GCM seal; returns ciphertext concatenated with 16-byte tag
export function aeadSeal(
  plaintext: Uint8Array,
  key32: Uint8Array,
  nonce12: Uint8Array,
  aad?: Uint8Array
): Buffer {
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key32), Buffer.from(nonce12));
  if (aad && aad.length) cipher.setAAD(Buffer.from(aad));
  const c1 = cipher.update(Buffer.from(plaintext));
  const c2 = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([c1, c2, tag]);
}

// AES-256-GCM open; input must be ciphertext+tag
export function aeadOpen(
  cipherAndTag: Uint8Array,
  key32: Uint8Array,
  nonce12: Uint8Array,
  aad?: Uint8Array
): Buffer {
  if (cipherAndTag.length < 16) throw new Error('cipher too short');
  const ct  = Buffer.from(cipherAndTag.slice(0, cipherAndTag.length - 16));
  const tag = Buffer.from(cipherAndTag.slice(cipherAndTag.length - 16));
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key32), Buffer.from(nonce12));
  if (aad && aad.length) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  const p1 = decipher.update(ct);
  const p2 = decipher.final();
  return Buffer.concat([p1, p2]);
}

// Kyber768 KEM via local binary; we spawn and parse its JSON output
const execFile = promisify(_execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const BIN = resolve(
  ROOT,
  `target/release/kem-cli${process.platform === 'win32' ? '.exe' : ''}`
);

// Execute CLI and parse stdout JSON
async function run(args: string[]) {
  const { stdout } = await execFile(BIN, args, {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}

// Kyber768 keypair as raw bytes
export async function kemKeygen() {
  const out = await run(['gen']);
  return { pk: b64ToU8(out.pkB64), sk: b64ToU8(out.skB64) };
}

// Encapsulate to pk; derive a 32-byte AEAD key via HKDF
export async function kemEncapsulate(pk: Uint8Array) {
  const out = await run(['encap', '--pk', u8ToB64(pk)]);
  const ss = b64ToU8(out.ssB64);
  const key = crypto.hkdfSync(
    'sha256',
    Buffer.from(ss),
    Buffer.alloc(0),
    Buffer.from('zk-chat:kyber768:aes256gcm:v1'),
    32
  );
  return { ct: b64ToU8(out.ctB64), key: new Uint8Array(key) };
}

// Decapsulate with sk and ct; returns the same 32-byte AEAD key
export async function kemDecapsulate(ct: Uint8Array, sk: Uint8Array) {
  const out = await run(['decap', '--sk', u8ToB64(sk), '--ct', u8ToB64(ct)]);
  const ss = b64ToU8(out.ssB64);
  const key = crypto.hkdfSync(
    'sha256',
    Buffer.from(ss),
    Buffer.alloc(0),
    Buffer.from('zk-chat:kyber768:aes256gcm:v1'),
    32
  );
  return new Uint8Array(key);
}
