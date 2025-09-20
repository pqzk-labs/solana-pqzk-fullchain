// Local key bootstrap: ensure SLH-DSA and Kyber768 keys exist under ./keys as base64 JSON.

import fs from 'fs/promises';
import path from 'node:path';
import {
  slhKeygen,
  PARAM,
  deriveVkFromSk,
  b64ToU8,
  kemKeygen,
} from './utils/crypto.ts';

const DIR = 'keys';

// SLH-DSA files
const SLH_PUB = path.join(DIR, 'slh_pub.json'); // { param, pkB64 }
const SLH_SEC = path.join(DIR, 'slh_sec.json'); // { param, skB64 }

// Kyber768 KEM files
const KEM_PUB = path.join(DIR, 'kem_pub.json'); // { scheme, pkB64 }
const KEM_SEC = path.join(DIR, 'kem_sec.json'); // { scheme, skB64 }

await fs.mkdir(DIR, { recursive: true });

// Read existing SLH-DSA, otherwise regenerate
let pkB64: string | undefined;
let skB64: string | undefined;
let paramPub: string | undefined;
let paramSec: string | undefined;

try {
  ({ pkB64, param: paramPub } = JSON.parse(await fs.readFile(SLH_PUB, 'utf8')));
  ({ skB64, param: paramSec } = JSON.parse(await fs.readFile(SLH_SEC, 'utf8')));
} catch {}

// Enforce matching PARAM to avoid mixing variants
if (paramPub !== PARAM || paramSec !== PARAM) {
  pkB64 = undefined;
  skB64 = undefined;
}

let regenerated = false;
if (!pkB64 || !skB64) {
  const kp = slhKeygen();
  pkB64 = kp.pkB64;
  skB64 = kp.skB64;
  regenerated = true;
  await fs.writeFile(SLH_PUB, JSON.stringify({ param: PARAM, pkB64 }));
  await fs.writeFile(SLH_SEC, JSON.stringify({ param: PARAM, skB64 }));
}

// Show derived VK pieces for quick inspection
const vkBytes = deriveVkFromSk(skB64!);
const seedHex = Buffer.from(vkBytes.slice(0, 16)).toString('hex');
const rootHex = Buffer.from(vkBytes.slice(16)).toString('hex');
console.log(regenerated ? 'SLH-DSA keypair generated ✅' : 'SLH-DSA keypair exists ✅');
console.log('pk_seed =', seedHex);
console.log('pk_root =', rootHex);

// Read or create Kyber768 keys
let kemPkB64: string | undefined;
let kemSkB64: string | undefined;

try {
  ({ pkB64: kemPkB64 } = JSON.parse(await fs.readFile(KEM_PUB, 'utf8')));
  ({ skB64: kemSkB64 } = JSON.parse(await fs.readFile(KEM_SEC, 'utf8')));
} catch {}

if (!kemPkB64 || !kemSkB64) {
  const { pk, sk } = await kemKeygen();
  kemPkB64 = Buffer.from(pk).toString('base64');
  kemSkB64 = Buffer.from(sk).toString('base64');
  await fs.writeFile(KEM_PUB, JSON.stringify({ scheme: 'kyber768', pkB64: kemPkB64 }));
  await fs.writeFile(KEM_SEC, JSON.stringify({ scheme: 'kyber768', skB64: kemSkB64 }));
  console.log('Kyber768 KEM keypair generated ✅');
} else {
  console.log('Kyber768 KEM keypair exists ✅');
}

// Quick size check
const pk = b64ToU8(kemPkB64!);
console.log('KEM pk bytes =', pk.length);
