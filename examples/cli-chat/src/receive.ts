// Receiver flow: find a ChatMsg for me, read and check the signature buffer, verify SLH-DSA,
// decapsulate the Kyber key, then decrypt the AES-256-GCM payload.

import { program, provider } from './utils/sdk.ts';
import { slhVerify, kemDecapsulate, aeadOpen } from './utils/crypto.ts';
import fs from 'fs/promises';
import { PublicKey } from '@solana/web3.js';
import { dirname, resolve, join as pathJoin } from 'path';
import { fileURLToPath } from 'url';
import crypto from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CACHE_DIR = resolve(__dirname, '../.cache');

// Account layout offsets mirrored from on-chain structs
const BUF_HEAD = 8 + (32 + 4 + 32); // 76
const RECIPIENT_OFFSET = 8 + 32; // 40

const me = provider.wallet.publicKey;
console.log('[DBG] programId     =', program.programId.toBase58());
console.log('[DBG] me            =', me.toBase58());

// Try pinned chat first for faster iteration
let pinnedChat: string | null = null;
try {
  const jc = JSON.parse(await fs.readFile(pathJoin(CACHE_DIR, 'last_chat.json'), 'utf8'));
  if (jc?.chatPda && jc?.programId === program.programId.toBase58()) {
    pinnedChat = jc.chatPda;
    console.log('[DBG] pinned chat   =', pinnedChat);
  }
} catch {}

// List all messages addressed to me using a memcmp filter on recipient
const filter = [{ memcmp: { offset: RECIPIENT_OFFSET, bytes: me.toBase58() } }];
const all = await program.account.chatMsg.all(filter);
console.log('[DBG] msgsRaw count =', all.length);

// BN or number handling for sort
const toNum = (x: any) => (typeof x === 'number' ? x : Number(x.toString()));
const msgsSorted = (pinnedChat ? all.filter(m => m.publicKey.toBase58() === pinnedChat) : all)
  .map((m) => ({ pubkey: m.publicKey, acc: m.account }))
  .sort((a, b) => toNum(b.acc.slot) - toNum(a.acc.slot));

if (!msgsSorted.length) throw new Error('no message found');
const chosen = msgsSorted[0];
console.log(
  `[DBG] chat=${chosen.pubkey.toBase58()} slot=${toNum(chosen.acc.slot)} ` +
  `sigPda=${chosen.acc.sigPda.toBase58()} cipherLen=${chosen.acc.cipherLen} kemLen=${chosen.acc.kemLen} ` +
  `sigLen=${chosen.acc.sigLen}`
);

// Read signature bytes from sig buffer account and check size
const sigPda = chosen.acc.sigPda as PublicKey;
const sigAi  = await provider.connection.getAccountInfo(sigPda);
if (!sigAi) throw new Error('signature PDA not found');

let sigLen = Number(chosen.acc.sigLen ?? 0);
if (!Number.isFinite(sigLen) || sigLen <= 0) throw new Error('invalid sigLen');

if (sigAi.data.length < BUF_HEAD + sigLen) {
  throw new Error(`sig account too small: have=${sigAi.data.length}, need>=${BUF_HEAD + sigLen}`);
}
const sigRaw = Buffer.from(sigAi.data.subarray(BUF_HEAD, BUF_HEAD + sigLen));

// Tamper check by comparing recorded hash and local hash
const sigHashOnchain = Buffer.from(chosen.acc.sigHash as number[]);
const sigHashLocal   = crypto.createHash('sha256').update(sigRaw).digest();
if (!sigHashLocal.equals(sigHashOnchain)) {
  throw new Error('sig hash mismatch');
}

// Recreate signed blob and verify SLH-DSA
const payload  = Uint8Array.from(chosen.acc.payload);
const cipher   = payload.slice(0, chosen.acc.cipherLen);
const kemStart = chosen.acc.cipherLen;
const kemEnd   = kemStart + chosen.acc.kemLen;
const kemCt    = payload.slice(kemStart, kemEnd);

const slotBig = typeof chosen.acc.slot === 'number' ? BigInt(chosen.acc.slot) : BigInt(chosen.acc.slot.toString());
const slotBuf = Buffer.alloc(8); slotBuf.writeBigUInt64LE(slotBig);

const blob = Buffer.concat([Buffer.from(cipher), Buffer.from(kemCt), Buffer.from(chosen.acc.nonce), slotBuf]);

// For this demo the sender is self; in real apps fetch sender VK from app storage
const { pkB64: slhPkB64 } = JSON.parse(await fs.readFile('keys/slh_pub.json', 'utf8'));
const slhPk = Uint8Array.from(Buffer.from(slhPkB64, 'base64'));

const ok = slhVerify(blob, sigRaw, slhPk);
console.log('[DBG] slhVerify     =', ok);
if (!ok) throw new Error('SLH-DSA verify NG');

// Recover AEAD key and decrypt the message
const { skB64: kemSkB64 } = JSON.parse(await fs.readFile('keys/kem_sec.json', 'utf8'));
const kemSk = Uint8Array.from(Buffer.from(kemSkB64, 'base64'));
const aeadKey = await kemDecapsulate(kemCt, kemSk);
const plaintext = aeadOpen(cipher, aeadKey, Uint8Array.from(chosen.acc.nonce));

console.log('PLAINTEXT =', plaintext.toString());
console.log('receive ✅');
