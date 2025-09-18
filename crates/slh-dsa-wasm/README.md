# 🧩 slh‑dsa‑wasm

WASM bindings for SLH‑DSA (SHA2‑128s). Provides key generation, signing, verification, and deriving the verifying‑key bytes from a secret key for use in JavaScript/TypeScript.

## 🔧 API surface
- **generate_keypair()** -> { public_key, private_key }
- **vk_bytes_from_sk(sk: &[u8])** -> Vec<u8>
- **sign(msg, sk_bytes)** -> Vec<u8>
- **verify(msg, sig_bytes, pk_bytes)** -> bool

Parameters: SHA2‑128s variant  
Sizes: sk 64 bytes, pk 32 bytes, sig 7,856 bytes

## ⚡ Build
```
wasm-pack build --target nodejs --out-dir pkg/slh_dsa_wasm
```
The CLI demo imports from pkg/slh_dsa_wasm and runs under Node.

## 📝 Notes
This crate disables default features of slh-dsa to fit no_std and SBF constraints upstream.  
For browsers, adjust the wasm-pack target accordingly.
