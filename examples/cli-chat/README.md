# 🚀 CLI chat demo (PQZK)

End‑to‑end demo that runs on Solana devnet:
- Encrypts a short message with AES‑256‑GCM using a Kyber768‑derived key
- Generates a STARK proof bound to SHA256(cipher)
- Signs cipher || kem || nonce || slot_le with SLH‑DSA SHA2‑128s (WASM)
- Uploads body and signature in chunks, finalizes on chain, verifies STARK
- Receives and decrypts the message

## ⚙️ Setup

Prereqs: Node, Rust + Cargo, wasm‑pack, Anchor.
```
npm --prefix examples/cli-chat run setup   # builds slh-dsa-wasm and kem-cli
```
Environment:
- RPC defaults to devnet; set RPC_URL if needed
- Wallet defaults to ~/.config/solana/id.json

## ▶️ Run
```
npm --prefix examples/cli-chat run keys
npm --prefix examples/cli-chat run upload
npm --prefix examples/cli-chat run finalize
npm --prefix examples/cli-chat run receive
```
What happens:
- keys creates SLH‑DSA and Kyber768 keypairs under examples/cli-chat/keys
- upload encrypts, proves, signs, and uploads buffers (≤ 900‑byte chunks)
- finalize calls finalize_sig then verify_stark, prints consumed CU
- receive re‑fetches accounts, checks signature hash, verifies SLH‑DSA, decapsulates, and decrypts
- Expected output ends with PLAINTEXT = Hello world! and both steps marked done.

## 🛠 Implementation notes
KEM operations use the local kem-cli binary for Kyber768
SLH‑DSA is provided by crates/slh-dsa-wasm (wasm‑pack build)
The demo uses self as recipient for simplicity; real apps would manage recipient keys and policy off chain
