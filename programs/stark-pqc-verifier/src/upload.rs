//! Chunked upload for (A) message body and (B) signature buffers.
//!
//! DoS control via hash-chaining: each chunk provides SHA256(prev_chain || data).
//! Stable offsets and bounded chunk size to keep CU predictable under SBF.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;

use crate::state::{BufferPda, MAX_CHAT_PAYLOAD, CHAINED_HASH_LEN, BUF_HEAD, MAX_SIG_PAYLOAD};

/// Common helper: write one chunk into a BufferPda with hash-chaining.
fn write_chunk(
    buf: &mut Account<BufferPda>,
    _who: &Signer,
    offset: u32,
    data:   Vec<u8>,
    next_hash: [u8; CHAINED_HASH_LEN],
    hard_max: usize,
) -> Result<()> {
    require!(data.len() <= 900, UploadError::ChunkTooLarge);
    require!(offset as usize == buf.length as usize, UploadError::OffsetMismatch);
    require!((offset as usize + data.len()) <= hard_max, UploadError::MsgTooBig);

    let calc = hashv(&[&buf.sha_chain, &data[..]]).to_bytes();
    require!(calc[..] == next_hash[..], UploadError::HashMismatch);

    let acc_info = buf.to_account_info();
    let mut dst  = acc_info.data.borrow_mut();
    let start = BUF_HEAD + offset as usize;
    dst[start .. start + data.len()].copy_from_slice(&data);

    buf.length    += data.len() as u32;
    buf.sha_chain  = next_hash;
    Ok(())
}

#[error_code]
pub enum UploadError {
    #[msg("chunk > 900 bytes")] ChunkTooLarge,
    #[msg("offset mismatch")]   OffsetMismatch,
    #[msg("buffer overflow")]   MsgTooBig,
    #[msg("hash mismatch")]     HashMismatch,
    #[msg("signature buffer is frozen (finalized)")] AlreadyFinalized,
}

/// Accounts for appending to the body buffer (buf).
#[derive(Accounts)]
pub struct UploadBody<'info> {
    #[account(mut, seeds=[b"buf", sender.key().as_ref()], bump, owner=crate::ID)]
    pub buffer: Account<'info, BufferPda>,
    pub sender: Signer<'info>,
}

/// Appends a body chunk (cipher || kem || proof) with hash-chaining.
pub fn handle_upload_body(
    ctx: Context<UploadBody>,
    offset: u32,
    data:   Vec<u8>,
    next_hash: [u8; CHAINED_HASH_LEN],
) -> Result<()> {
    write_chunk(&mut ctx.accounts.buffer, &ctx.accounts.sender, offset, data, next_hash, MAX_CHAT_PAYLOAD)
}

/// Accounts for appending to the signature buffer (sig).
#[derive(Accounts)]
#[instruction(recipient: Pubkey, slot: u64)]
pub struct UploadSignature<'info> {
    #[account(
        mut,
        seeds=[b"sig", sender.key().as_ref(), recipient.key().as_ref(), &slot.to_le_bytes()],
        bump, owner=crate::ID
    )]
    pub buffer: Account<'info, BufferPda>,
    pub sender: Signer<'info>,
    /// CHECK: recipient is used only for PDA seeds.
    pub recipient: UncheckedAccount<'info>,

    /// CHECK: refuse uploads if already finalized (existence check).
    #[account(seeds=[b"msg", sender.key().as_ref(), recipient.key().as_ref(), &slot.to_le_bytes()], bump)]
    pub chat_msg: UncheckedAccount<'info>,
}

/// Appends a signature chunk with hash-chaining.
pub fn handle_upload_signature(
    ctx: Context<UploadSignature>,
    _recipient: Pubkey,
    _slot: u64,
    offset: u32,
    data:   Vec<u8>,
    next_hash: [u8; CHAINED_HASH_LEN],
) -> Result<()> {
    let chat_ai = ctx.accounts.chat_msg.to_account_info();
    require!(chat_ai.data_is_empty(), UploadError::AlreadyFinalized);
    // Enforces the signature PDA payload cap (10,156 bytes).
    write_chunk(
        &mut ctx.accounts.buffer,
        &ctx.accounts.sender,
        offset,
        data,
        next_hash,
        MAX_SIG_PAYLOAD,
    )
}
