# 🔬 stark‑prover

Minimal STARK prover used by the demo.  
Produces a Winterfell 0.12 proof for a one‑column affine‑counter AIR:  
`x_{t+1} = x_t + inc`, with boundary assertions at steps 0 and last.

## 🔗 Binding to the ciphertext
The prover expects a SHA‑256 digest of the ciphertext. It derives public inputs as:
- seed = LE_u64(digest[0..8])
- inc = LE_u64(digest[8..16])

This matches the on‑chain verifier, so the proof is bound to the uploaded ciphertext.

## 💻 CLI
```
cargo run -p stark-prover --release -- gen <sha256_hex>
```
Writes proof.bin to the current directory.  
The demo calls this from examples/cli-chat/src/upload.ts.

## ⚙️ Internals
- Winterfell 0.12 with Sha2_256, f128 base field
- Trace length 8 for clarity
- Proof options target about 128‑bit conjectured security on the verifier side

## 🛠 Build and test
```
cargo build -p stark-prover --release
cargo test  -p stark-prover
```
