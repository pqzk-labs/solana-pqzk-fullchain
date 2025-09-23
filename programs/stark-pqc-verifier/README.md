# 🛡 stark‑pqc‑verifier

Solana program that verifies **two things** for a single message:  
- **SLH‑DSA SHA2‑128s signature**  
- **Winterfell STARK proof** for a minimal affine‑counter AIR  

Designed for CPI use and predictable CU on SBF.  

## ⚙️ How it works
1️⃣ **Upload in chunks**
- Body buffer: cipher || kem_ciphertext || stark_proof
- Signature buffer: fixed‑size SLH‑DSA signature

2️⃣ **Finalize in two steps**
- finalize_sig(cipher_len, kem_len, nonce, slot, slh_pub)
  - Verifies SLH‑DSA over cipher || kem || nonce || slot_le
  - Writes a ChatMsg account with metadata and a hash of the signature
verify_stark()
- Computes d = SHA256(cipher)
  - Public inputs: seed = LE_u64(d[0..8]), inc = LE_u64(d[8..16])
  - Verifies the embedded Winterfell proof against the affine‑counter AIR

## 📂 Accounts and limits
BufferPda (for body or signature)
- Persistent fields: sender, length, sha_chain
- Account space: 10,232 bytes; chunk size ≤ 900 bytes

ChatMsg
- Header ≈ 164 bytes, payload up to 10,068 bytes
- Payload is cipher || kem || proof; also records sig_hash for tamper evidence

Signature length: 7,856 bytes (SLH‑DSA SHA2‑128s)

## 📜 Instructions (Anchor)
- **init_buffer()** — create/reset the body buffer PDA
- **init_signature(recipient, slot)** — create/reset the signature buffer PDA
- **upload_body(off, data, hash)** — append with hash chaining
- **upload_signature(recipient, slot, off, data, hash)** — append with hash chaining
- **finalize_sig(cipher_len, kem_len, nonce, slot, slh_pub)** — verify signature and persist ChatMsg
- **verify_stark()** — verify the STARK proof inside ChatMsg

## 🧵 Heap and CU
The program ships a bump allocator. Clients must request matching heap frames:  
For finalize_sig: request about 128 KiB  
For verify_stark: request about 256 KiB

Also set a CU limit high enough for verification. See examples/cli-chat.

## 🚀 Build and deploy
```
anchor build
anchor deploy
```
Program id (devnet): `CECNRbDxFQVfWiQwvG8qcSGPGSk8eLWraBCERcdL5DKT`

## 🔐 Security note (128‑bit vs 127‑bit)
> Winterfell applies a conservative −1 in its conjectured‑security calculation; see winter_air/proof/security.rs::ConjecturedSecurity::compute().  
> Specifically, it evaluates min(min(field_security, query_security) - 1, collision_resistance).  
> With `f128` (128-bit) + SHA-256 (≈128-bit), the cap is **127 bits**.  
> → The verifier uses `AcceptableOptions::MinConjecturedSecurity(127)` while targeting a 128-bit profile.
