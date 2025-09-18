//! # Module overview
//! This program demonstrates a full on-chain verification pipeline combining:
//! 1. SLH-DSA (SHA2-128s): post-quantum signature verification
//! 2. STARK verification: using Winterfell 0.12 for a minimal affine-counter AIR
//!
//! # Instruction set
//! init_buffer / init_signature: initialize PDA buffers used for streaming uploads.
//! upload_body / upload_signature: chunked upload with hash-chaining to mitigate DoS.
//! finalize_sig: verify SLH-DSA and persist a ChatMsg account (cipher|kem|proof).
//! verify_stark: verify the STARK proof against SHA-256(cipher)-derived public inputs.

#![allow(unexpected_cfgs)] // Keep until Anchor's cfg layout is simplified
#![allow(deprecated)] // Remove once Anchor moves to AccountInfo::resize()

use anchor_lang::prelude::*;

#[cfg(all(feature = "custom-heap", any(target_arch = "bpf", target_os = "solana")))]
mod heap;

#[cfg(all(feature = "custom-heap", any(target_arch = "bpf", target_os = "solana")))]
#[link_section = ".rodata"]
#[global_allocator]
static GLOBAL_ALLOC: heap::BpfBumpAlloc = heap::BpfBumpAlloc;

mod state;
mod crypto;
mod init;
mod upload;
mod finalize;

// Program ID
declare_id!("CECNRbDxFQVfWiQwvG8qcSGPGSk8eLWraBCERcdL5DKT");

// Re-exports
pub use init   ::{ InitBuffer, InitSignature };
pub use upload ::{ UploadBody, UploadSignature };
pub use finalize::{ FinalizeSig, VerifyStark };

// Anchor idl-build client account module names
pub mod __client_accounts_init_buffer      { pub use crate::InitBuffer; }
pub mod __client_accounts_init_signature   { pub use crate::InitSignature; }
pub mod __client_accounts_upload_body      { pub use crate::UploadBody; }
pub mod __client_accounts_upload_signature { pub use crate::UploadSignature; }
pub mod __client_accounts_finalize_sig     { pub use crate::FinalizeSig; }
pub mod __client_accounts_verify_stark     { pub use crate::VerifyStark; }

#[program]
pub mod stark_pqc_verifier {
    use super::*;

    /// Initializes the body buffer PDA used for streaming uploads, zeros length and sha_chain.
    pub fn init_buffer(ctx: Context<InitBuffer>) -> Result<()> {
        init::handle_init_buffer(ctx)
    }

    /// Initializes the signature buffer PDA for a (sender, recipient, slot) tuple.
    pub fn init_signature(ctx: Context<InitSignature>, recipient: Pubkey, slot: u64) -> Result<()> {
        init::handle_init_signature(ctx, recipient, slot)
    }

    /// Appends a body chunk to the body buffer (cipher || kem || proof) with hash-chaining.
    pub fn upload_body(ctx: Context<UploadBody>, off: u32, data: Vec<u8>, hash: [u8; 32]) -> Result<()> {
        upload::handle_upload_body(ctx, off, data, hash)
    }

    /// Appends a signature chunk to the signature buffer with hash-chaining.
    pub fn upload_signature(
        ctx: Context<UploadSignature>,
        recipient: Pubkey,
        slot: u64,
        off: u32,
        data: Vec<u8>,
        hash: [u8; 32],
    ) -> Result<()> {
        upload::handle_upload_signature(ctx, recipient, slot, off, data, hash)
    }

    /// Step 1: Verifies SLH-DSA and persists a ChatMsg.
    pub fn finalize_sig(
        ctx       : Context<FinalizeSig>,
        cipher_len: u32,
        kem_len   : u32,
        nonce     : [u8; 12],
        slot      : u64,
        slh_pub   : [u8; 32],
    ) -> Result<()> {
        finalize::handle_finalize_sig(ctx, cipher_len, kem_len, nonce, slot, slh_pub)
    }

    /// Step 2: Verifies the STARK proof for the affine-counter AIR.
    pub fn verify_stark(ctx: Context<VerifyStark>) -> Result<()> {
        finalize::handle_verify_stark(ctx)
    }
}
