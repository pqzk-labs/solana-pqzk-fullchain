# 📦 Third‑Party Patches
This README documents the local patches applied to the vendored crates under this third-party directory.  
Each section summarizes what changed, how it works, build notes, compatibility, and caveats.

## 🔑 slh-dsa
SLH‑DSA for Solana SVM

### Scope
Adapts slh-dsa for Solana and Anchor projects that require Rust 2021 and a low‑memory on‑chain environment.  
Adds a **streaming verifier** for SLH‑DSA‑SHA2‑128s, routes SHA‑256 to the Solana hashv syscall on chain, and backports dependencies for Solana compatibility.

### Changes
- **Rust and editions**  
  Sets edition = 2021 and rust-version = 1.73.
- **Dependencies**  
  Pins hybrid-array = 0.2 with extra-sizes.  
  Uses signature = 2.2 with rand_core only.  
  Adds solana-program = 2.3.0 and wasm-bindgen for wasm32.
- **Hashing path**  
  Introduces sha256_syscall that uses solana_program::hash::hashv on chain and sha2::Sha256 off chain.  
  Updates SHA2 message hashing to accept multiple byte slices to reduce copies.
- **On‑chain verifier**  
  Adds src/onchain_sha2.rs with verify_sha2_128s(msg, sig, vk) that verifies SLH‑DSA‑SHA2‑128s from slices without building large structs.
- **API surface**  
  Exposes pub mod onchain_sha2.  
  Extends ParameterSet with ALGORITHM_OID and provides provisional OIDs for SHA2 parameter sets.
- **Features**  
  Defaults to ["alloc"].

### How it Works
- **On chain**  
  Streams over the signature and computes H_msg via hashv plus MGF1.  
  Reconstructs FORS roots and the XMSS hypertree layer by layer and compares the final root to the verifying key.  
  Avoids large temporaries to respect BPF stack limits.
- **Off chain**  
  Uses sha2::{Sha256,Sha512} with the same logic. Accepts &[&[u8]] where helpful to avoid copies.

### Build Notes
Requires Rust 1.73 and Edition 2021.  
Use solana-program = 2.3.0 in Solana programs.  
The syscall shim is gated by #[cfg(target_os = "solana")]. When not set, it falls back to software SHA‑256.  
no_std on BPF is preserved where applicable. The streaming verifier compiles with #![cfg_attr(target_arch = "bpf", no_std)].

### Usage on Chain
use slh_dsa::onchain_sha2::verify_sha2_128s;  
// msg: &[u8]  
// sig: &[u8] serialized SLH‑DSA‑SHA2‑128s signature (7856 bytes)  
// vk:  &[u8] verifying key (pk_seed || pk_root), 32 bytes for 128s  
verify_sha2_128s(msg, sig, vk)?;

### Limitations
- Supports SHA2‑128s only on chain  
- Context is treated as empty in the on‑chain path.
- OIDs are provisional and may change.
- Some off‑chain paths still allocate; the on‑chain verifier minimizes allocations by design.

### Compatibility
The new ALGORITHM_OID associated constant may require minor changes in downstream trait bounds.  
Default feature changes can affect builds that relied on pkcs8/alloc being enabled implicitly.

### Security
Not independently audited.  
The syscall hashing path and streaming verifier target Solana constraints and should be reviewed for your threat model.


## 🔒 winter-crypto
SHA‑256 Hasher for Winterfell on Solana

### Scope
Vendors a patched winter-crypto that adds a SHA‑256 hasher optimized for Solana BPF.

### Changes
- Adds hash/sha2/mod.rs with Sha2_256.
- Reexports Sha2_256 from hash/mod.rs.
- Adds dependencies:
  - sha2 = "0.10" for host hashing
  - solana-program = "2.3.0" for on‑chain hashv

### How it Works
- On BPF → Serializes inputs once and hashes via a single hashv call to minimize syscalls.
- On host → Uses sha2::Sha256 with incremental updates.
- Element hashing → Hashes canonical fields directly as bytes. Otherwise serializes through a ByteWriter wrapper.

### Build Notes
- Solana BPF  
Request a sufficient heap frame if you hash large inputs because BPF buffers the serialized input before the single hashv call.
- Crate sources  
Removes upstream local path dependencies so Cargo pulls published crates.
- Optional features  
If you do not want to link solana-program off chain, gate it with a feature:
```
[features]
default = ["std"]
std = ["blake3/std", "math/std", "sha3/std", "utils/std", "sha2/std"]
solana = ["dep:solana-program"]

[dependencies]
sha2 = { version = "0.10", default-features = false }
solana-program = { version = "2.3.0", default-features = false, optional = true }
```
### Performance Notes
The BPF path reduces syscalls and compute units in hashing‑heavy code.  
It allocates a temporary buffer equal to the serialized input size. Plan heap usage accordingly.

### Compatibility and Behavior
Digest size is 32 bytes with 128‑bit collision security, matching other 256‑bit hashers.  
merge and merge_many hash concatenated digests. merge_with_int hashes seed || value_le.  
Merkle roots change if you switch hashers. Use the same hasher on producer and verifier.

### Migration Checklist
Import Sha2_256 and pass it to Winterfell generics where a hasher is required.  
Ensure reexports match your import paths.  
On Solana, request a heap frame large enough for the biggest payloads.  
Rebuild and rerun tests and benches for Merkle and verifier paths.

### Troubleshooting
- Unresolved import → Add or fix the reexport so Sha2_256 appears under your expected path.
- Link errors with solana-program → Align the version across the workspace or gate with a feature.
- BPF heap OOM → Increase ComputeBudgetProgram::requestHeapFrame for worst‑case input size.


## 🧮 winter-fri
Patched Winter FRI Verifier for Solana SBF Stack Limit

### Scope
Addresses Solana BPF’s ≈4 KiB per‑call stack limit that could be exceeded by the FRI verifier when LLVM inlines batch interpolation.

### Changes
Moves batch interpolation into a non‑inlined helper to keep large temporaries off the caller’s frame
```
#[inline(never)]
fn interpolate_rows<E: FieldElement, const N: usize>(
    xs: &[[E; N]],
    ys: &[[E; N]],
) -> Vec<[E; N]> {
    polynom::interpolate_batch(xs, ys)
}
// call site:
let row_polys = interpolate_rows(&xs, &layer_values);
```
Marks the verifier core verify_generic as #[inline(never)].

### Effect
- Preserves semantics and error behavior
- Reduces stack pressure under SBF limits
- Adds only one extra call and negligible overhead
- Leaves heap behavior unchanged

### Notes
The patch targets stack usage.  
Request a sufficiently large heap frame for STARK verification as needed.

### Optional Gating
Apply attributes only on chain if desired:
```
#[cfg_attr(any(target_arch = "bpf", target_os = "solana"), inline(never))]
fn interpolate_rows<...>(...) -> Vec<[E; N]> { ... }
#[cfg_attr(any(target_arch = "bpf", target_os = "solana"), inline(never))]
fn verify_generic<...>(...) -> Result<..., ...> { ... }
```
### Compatibility
- Works with Winterfell 0.12 as used here.
- No API changes for callers.
- Patch is small and easy to rebase when updating upstream.

### Rationale
> Move batch interpolation into a non‑inlined helper and keep the verifier core non‑inlined so each function’s stack frame stays below Solana SBF limits without changing verification behavior.
