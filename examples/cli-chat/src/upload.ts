// Sender flow: init PDAs, encrypt with AES using Kyber key, generate STARK proof, SLH-DSA sign,
// chunk upload for body and signature with hash-chaining, write finalize metadata.

import BN from 'bn.js';
import { program, provider } from './utils/sdk.ts';
import { slhSign, kemEncapsulate } from './utils/crypto.ts';
import fs from 'fs/promises';
import { PublicKey, SystemProgram } from '@solana/web3.js';
import { execSync } from 'node:child_process';
import crypto from 'node:crypto';
import { dirname, resolve, join as pathJoin } from 'path';
import { fileURLToPath } from 'url';

const __dirname    = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR     = resolve(__dirname, '../../..');
const PROVER_DIR   = resolve(ROOT_DIR, 'crates/stark-prover');   // local prover crate path
const CACHE_DIR    = resolve(__dirname, '../.cache');

const PLAINTEXT = Buffer.from('Hello world!', 'utf8');
const CHUNK_MAX = 900; // must match on-chain limit

// Helper for LE u64 in PDA seeds
const leBytes8 = (n: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };

// Demo uses self as recipient
const sender = provider.wallet.publicKey;
const recipient = sender;

console.log('[DBG] programId      =', program.programId.toBase58());
console.log('[DBG] wallet         =', sender.toBase58());
console.log('[DBG] recipient      =', recipient.toBase58());

// Slot is included in seeds to avoid collisions across runs
const slot = await provider.connection.getSlot('finalized');
const slotBN = new BN(slot.toString(), 10);

// Derive PDAs for buffer, signature, and final ChatMsg
const [bufPda] = PublicKey.findProgramAddressSync(
  [Buffer.from('buf'), sender.toBuffer()],
  program.programId
);
const [sigPda] = PublicKey.findProgramAddressSync(
  [Buffer.from('sig'), sender.toBuffer(), recipient.toBuffer(), leBytes8(BigInt(slot))],
  program.programId
);
const [predictedChatPda] = PublicKey.findProgramAddressSync(
  [Buffer.from('msg'), sender.toBuffer(), recipient.toBuffer(), leBytes8(BigInt(slot))],
  program.programId
);

// Initialize PDAs
await program.methods
  .initBuffer()
  .accountsStrict({
    buffer: bufPda,
    payer: sender,
    systemProgram: SystemProgram.programId,
  })
  .rpc();

await program.methods
  .initSignature(recipient, slotBN)
  .accountsStrict({
    buffer: sigPda,
    recipient,
    payer: sender,
    systemProgram: SystemProgram.programId,
  })
  .rpc();
console.log('init buf & sig ✅');

// Encrypt with AES-256-GCM using a Kyber-derived key
const { pkB64: kemPkB64 } = JSON.parse(await fs.readFile('keys/kem_pub.json', 'utf8'));
const kemPk = Uint8Array.from(Buffer.from(kemPkB64, 'base64'));
const { ct: kemCiphertext, key: aesKey } = await kemEncapsulate(kemPk);
const nonce = crypto.randomBytes(12);
const cipher = (() => {
  const c = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  const enc = Buffer.concat([c.update(PLAINTEXT), c.final()]);
  const tag = c.getAuthTag();
  return Buffer.concat([enc, tag]);
})();

// Generate STARK proof bound to SHA256(cipher)
const sha256 = crypto.createHash('sha256').update(cipher).digest();
execSync(
  `cargo run -p stark-prover --quiet --release -- gen ${sha256.toString('hex')}`,
  { cwd: PROVER_DIR }
);
const proof = await fs.readFile(resolve(PROVER_DIR, 'proof.bin'));

// SLH-DSA sign over cipher, KEM ct, nonce, slot
const { skB64 } = JSON.parse(await fs.readFile('keys/slh_sec.json', 'utf8'));
const sk        = Uint8Array.from(Buffer.from(skB64, 'base64'));

const slotBuf = Buffer.alloc(8); slotBuf.writeBigUInt64LE(BigInt(slot));
const signBlob = Buffer.concat([Buffer.from(cipher), Buffer.from(kemCiphertext), nonce, slotBuf]);
const sigU8 = await slhSign(signBlob, sk);
const SIG   = Buffer.from(sigU8);
const SIG_LEN = SIG.length;

// Upload signature with hash-chaining
async function sendChunksSig(pda: PublicKey, raw: Buffer) {
  let offset = 0;
  let hash: Buffer = Buffer.alloc(32); // zero seed
  let n = 0;
  while (offset < raw.length) {
    const chunk = raw.slice(offset, offset + CHUNK_MAX);
    hash = crypto.createHash('sha256').update(Buffer.concat([hash, chunk])).digest();
    await program.methods
      .uploadSignature(recipient, slotBN, offset, chunk, Array.from(hash))
      .accountsStrict({
        buffer   : pda,
        sender   : sender,
        recipient: recipient,
        chatMsg  : predictedChatPda, // detect finalized state
      })
      .rpc();
    console.log(`SIG chunk #${n}  len=${chunk.length}  offset=${offset}`);
    offset += chunk.length; n += 1;
  }
  if (offset !== SIG_LEN) throw new Error(`SIG upload truncated: sent ${offset} bytes`);
}

// Upload body in chunks
async function sendChunksBody(pda: PublicKey, raw: Buffer) {
  let offset = 0;
  let hash: Buffer = Buffer.alloc(32);
  while (offset < raw.length) {
    const chunk = raw.slice(offset, offset + CHUNK_MAX);
    hash = crypto.createHash('sha256').update(Buffer.concat([hash, chunk])).digest();
    await program.methods
      .uploadBody(offset, chunk, Array.from(hash))
      .accountsStrict({ buffer: pda, sender })
      .rpc();
    offset += chunk.length;
  }
}

// Compose body and send both buffers
const body = Buffer.concat([cipher, Buffer.from(kemCiphertext), proof]);
await sendChunksBody(bufPda, body);
await sendChunksSig(sigPda, SIG);
console.log('upload done ✅');

// Cache PDAs and sizes for inspection
await fs.mkdir(CACHE_DIR, { recursive: true });
await fs.writeFile(
  pathJoin(CACHE_DIR, 'last_post.json'),
  JSON.stringify({
    programId : program.programId.toBase58(),
    wallet    : sender.toBase58(),
    recipient : recipient.toBase58(),
    slot,
    chatPda   : predictedChatPda.toBase58(),
    bufPda    : bufPda.toBase58(),
    sigPda    : sigPda.toBase58(),
    sizes     : { cipher: cipher.length, kem: kemCiphertext.length, proof: proof.length, sig: SIG_LEN }
  }, null, 2)
);

// Metadata for finalize.ts
await fs.writeFile(
  'upload_meta.json',
  JSON.stringify({
    cipher_len: cipher.length,
    kem_len   : kemCiphertext.length,
    proof_len : proof.length,
    nonce     : [...nonce],
    slot,
    sigPda    : sigPda.toBase58(),
    recipient : recipient.toBase58(),
  })
);
