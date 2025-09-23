//! Provides a streaming verifier for SLH DSA SHA2 128s that fits the BPF 4 KiB stack
//! Uses Solana hashv for SHA 256 on chain and uses Sha256 off chain
//! Parses signature and XMSS layers directly from slices and avoids large temporary objects
//! Keeps steps aligned with FIPS 205 and returns signature errors on any mismatch

#![cfg_attr(target_arch = "bpf", no_std)]

use core::convert::TryInto;

use crate::signature::Error as SigErr;
use hybrid_array::{Array, ArraySize};

use typenum::consts::U14;
use typenum::Unsigned;

use crate::{
    address::{ForsTree, WotsHash},
    fors::ForsParams,
    hashes::{HashSuite, Sha2_128s},
    hypertree::HypertreeParams,
    util::{base_2b, split_digest},
    verifying_key::VerifyingKey,
    xmss::{XmssParams, XmssSig},
};

type P = Sha2_128s;                         // L1 / 128s
type N = <P as HashSuite>::N;               // 16 bytes
type BytesN = Array<u8, N>;

/// Declares the SLH DSA SHA2 128s signature length from FIPS 205
pub const SIG_LEN_128S: usize = 7_856;

/// Declares the XMSS height per layer for 128s, where H' equals 9
const H_PRIME: usize = 9;

/* SHA 256 helper that uses hashv on chain and falls back off chain */
#[inline]
fn sha256_syscall(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        use solana_program::hash::hashv;
        hashv(parts).to_bytes()
    }
    #[cfg(not(target_os = "solana"))]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..]);
        out
    }
}

/// Implements MGF1 with SHA256 and generates L bytes
fn mgf1_sha256<L: ArraySize>(seed: &[u8]) -> Array<u8, L> {
    let mut out = Array::<u8, L>::default();
    let mut off = 0usize;
    let mut ctr: u32 = 0;

    while off < L::USIZE {
        let block = sha256_syscall(&[seed, &ctr.to_be_bytes()]);
        let n = core::cmp::min(32, L::USIZE - off);
        out[off..off + n].copy_from_slice(&block[..n]);
        off += n;
        ctr = ctr.wrapping_add(1);
    }
    out
}

/// Verifies SLH DSA SHA2 128s in a streaming manner
/// Accepts raw message, raw signature and raw verifying key that equals pk_seed || pk_root
/// Returns Ok on success and returns Error on failure
#[inline(never)]
pub fn verify_sha2_128s(msg: &[u8], sig: &[u8], vk_raw: &[u8]) -> Result<(), SigErr> {
    // Check input length first to avoid work
    if sig.len() != SIG_LEN_128S {
        return Err(SigErr::new());
    }

    // Parse verifying key without allocation
    let vk = VerifyingKey::<P>::try_from(vk_raw).map_err(|_| SigErr::new())?;

    // Compute h_msg with empty context prefix [0, 0]
    let rand: BytesN = (&sig[..N::USIZE]).try_into().map_err(|_| SigErr::new())?;
    let ctx_prefix = [0u8; 2];

    // inner = SHA256(rand || pk_seed || pk_root || 0 || 0 || msg)
    let inner = sha256_syscall(&[
        rand.as_slice(),
        vk.pk_seed.as_ref(),
        vk.pk_root.as_slice(),
        &ctx_prefix,
        msg,
    ]);

    // seed = rand || pk_seed || inner
    let seed = rand
        .clone()
        .concat(vk.pk_seed.0.clone())
        .concat(Array::<u8, typenum::U32>(inner));

    // digest = MGF1 SHA256 over seed
    let digest = mgf1_sha256::<<P as HashSuite>::M>(seed.as_slice());

    // Split digest into md, idx_tree and idx_leaf
    let (md, mut idx_tree, idx_leaf0) = split_digest::<P>(&digest);

    // Derive K indices from md
    let msg_idx =
        base_2b::<<P as ForsParams>::K, <P as ForsParams>::A>(md.as_slice());

    // Process FORS in a streaming way
    let mut cursor = N::USIZE; // skip rand
    let mut roots = Array::<BytesN, U14>::default(); // K equals 14 for 128s

    let mut adrs = ForsTree::new(idx_tree, idx_leaf0);
    let adrs_roots = adrs.clone();

    for i in 0..<P as ForsParams>::K::USIZE {
        // Borrow sk_i as a slice view
        let sk: &BytesN = (&sig[cursor..cursor + N::USIZE])
            .try_into()
            .map_err(|_| SigErr::new())?;
        cursor += N::USIZE;

        let leaf_idx = ((i as u32) << <P as ForsParams>::A::U32) | msg_idx[i] as u32;
        adrs.tree_height.set(0);
        adrs.tree_index.set(leaf_idx);

        // Compute leaf
        let mut node = P::f(&vk.pk_seed, &adrs, sk);

        // Consume authentication path of A levels
        let mut idx = leaf_idx;
        for h in 0..<P as ForsParams>::A::USIZE {
            let sib: &BytesN = (&sig[cursor..cursor + N::USIZE])
                .try_into()
                .map_err(|_| SigErr::new())?;
            cursor += N::USIZE;

            adrs.tree_height.set(h as u32 + 1);
            adrs.tree_index.set(idx >> 1);

            node = if idx & 1 == 0 {
                P::h(&vk.pk_seed, &adrs, &node, sib)
            } else {
                P::h(&vk.pk_seed, &adrs, sib, &node)
            };
            idx >>= 1;
        }
        roots[i] = node;
    }

    // Hash FORS roots into a single root
    let mut root = P::t(&vk.pk_seed, &adrs_roots.fors_roots(), &roots);

    // Process hypertree layer by layer
    const MASK: u64 = (1u64 << H_PRIME) - 1;

    for layer in 0..<P as HypertreeParams>::D::USIZE {
        let (leaf, tree_addr) = if layer == 0 {
            (idx_leaf0, idx_tree)
        } else {
            let l = (idx_tree & MASK) as u32;
            idx_tree >>= H_PRIME;
            (l, idx_tree)
        };

        // Borrow this layer XMSS signature as a slice view
        let xmss_len = XmssSig::<P>::SIZE;
        if cursor + xmss_len > sig.len() {
            return Err(SigErr::new());
        }
        let xmss_sig = XmssSig::<P>::try_from(&sig[cursor..cursor + xmss_len])
            .map_err(|_| SigErr::new())?;
        cursor += xmss_len;

        // Configure address and derive next root
        let mut adrs_w = WotsHash::default();
        adrs_w.layer_adrs.set(layer as u32);
        adrs_w.tree_adrs_low.set(tree_addr);
        adrs_w.tree_adrs_high.set(0);
        adrs_w.key_pair_adrs.set(leaf);

        root = <P as XmssParams>::xmss_pk_from_sig(leaf, &xmss_sig, &root, &vk.pk_seed, &adrs_w);
    }

    // Compare final root with pk_root
    if root == vk.pk_root {
        Ok(())
    } else {
        Err(SigErr::new())
    }
}
