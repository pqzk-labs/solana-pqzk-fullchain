# 🔑 kem‑cli

Small Kyber768 KEM helper used by the demo. Prints one JSON object per command on stdout.

## 🛠 Commands
- **gen** - Outputs base64 public and secret keys and their lengths.
- **encap --pk <base64>** - Outputs base64 ciphertext and shared secret.
- **decap --sk <base64> --ct <base64>** - Outputs base64 shared secret.

## 💻 Examples
```
kem-cli gen
kem-cli encap --pk <pkB64>
kem-cli decap --sk <skB64> --ct <ctB64>
```
JSON fields:  
For gen: pkB64, skB64, plus pk_len, sk_len  
For encap: ctB64, ssB64, plus ct_len, ss_len  
For decap: ssB64, ss_len

## 🛠 Build
```
cargo build -p kem-cli --release
```
