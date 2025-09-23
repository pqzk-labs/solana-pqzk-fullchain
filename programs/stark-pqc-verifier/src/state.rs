//! On-chain state layout and size rationale.
//!
//! BufferPda: streaming buffer (body/signature uploads).
//! ChatMsg: finalized message (cipher|kem|proof + metadata). Max 10,240B to keep CU predictable.

use anchor_lang::prelude::*;

// Size constants
pub const MAX_ACCOUNT_BYTES: usize = 10_240; // Hard upper bound for allocation
pub const DISC_SIZE: usize = 8;
pub const META_HEAD: usize = 32 + 4 + 32; // sender(32) + len(4) + sha(32)
pub const BUF_HEAD : usize = DISC_SIZE + META_HEAD; // = 76
pub const CHAT_HEAD: usize = 164;
pub const MAX_CHAT_PAYLOAD: usize = MAX_ACCOUNT_BYTES - DISC_SIZE - CHAT_HEAD; // = 10,068
pub const BUF_ACCOUNT_SPACE: usize = META_HEAD + (MAX_ACCOUNT_BYTES - BUF_HEAD); // = 10,232
pub const MAX_SIG_PAYLOAD: usize = BUF_ACCOUNT_SPACE - BUF_HEAD; // = 10,156

// Signature and hashing
pub const CHAINED_HASH_LEN: usize = 32;
pub const SIG_BYTES: usize = crate::crypto::SIG_LEN;

#[account]
pub struct BufferPda {
    pub sender   : Pubkey,
    pub length   : u32,
    pub sha_chain: [u8; CHAINED_HASH_LEN],
}

/// Finalized chat message: payload = cipher || kem || proof (STARK proof).
#[account]
pub struct ChatMsg {
    pub sender    : Pubkey,
    pub recipient : Pubkey,
    pub cipher_len: u32,
    pub kem_len   : u32,
    pub nonce     : [u8; 12],
    pub slot      : u64,
    pub sig_pda   : Pubkey,
    pub sig_len   : u32,
    pub sig_hash  : [u8; 32],
    pub payload   : Vec<u8>, // cipher || kem || proof
}

#[error_code(offset = 7000)]
pub enum ErrorCode {
    #[msg("length mismatch")]           LenMismatch,
    #[msg("signature verify failed")]   SigFailed,
    #[msg("STARK proof verify failed")] ProofFailed,
}
