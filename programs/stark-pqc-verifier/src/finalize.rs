//! Finalization and STARK verification steps.
//!
//! Step 1: handle_finalize_sig
//! Reads body (cipher|kem|proof) from buf.
//! Verifies SLH-DSA (SHA2-128s) over cipher||kem||nonce||slot_le.
//! Persists ChatMsg with metadata and sig_hash (tamper-evidence). Auto-closes the body buffer (close = payer).
//!
//! Step 2: handle_verify_stark
//! Derives public inputs from SHA-256(cipher) → (seed, inc).
//! Verifies the Winterfell STARK proof for the affine-counter AIR.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;

use crate::{
    state::{
        BufferPda, ChatMsg, BUF_HEAD, CHAT_HEAD, MAX_CHAT_PAYLOAD, MAX_SIG_PAYLOAD, SIG_BYTES,
        ErrorCode,
    },
    crypto,
};

/// Accounts for Step 1 (signature finalization).
#[derive(Accounts)]
#[instruction(cipher_len: u32, kem_len: u32, nonce: [u8; 12], slot: u64, slh_pub: [u8; 32])]
pub struct FinalizeSig<'info> {
    #[account(
        mut,
        seeds=[b"buf", payer.key().as_ref()],
        bump,
        close = payer
    )]
    pub buffer: Account<'info, BufferPda>,

    #[account(
        mut,
        seeds=[b"sig", payer.key().as_ref(), recipient.key().as_ref(), &slot.to_le_bytes()],
        bump
    )]
    pub sigbuf: Account<'info, BufferPda>,

    #[account(
        init_if_needed, payer=payer,
        space=8 + CHAT_HEAD + buffer.length as usize,
        seeds=[b"msg", payer.key().as_ref(), recipient.key().as_ref(), &slot.to_le_bytes()],
        bump
    )]
    pub chat_msg: Account<'info, ChatMsg>,
    /// CHECK: recipient is app-layer identity; enforced via seeds only.
    pub recipient: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[allow(clippy::too_many_arguments)]
/// Verifies SLH-DSA and persists a ChatMsg.
/// Reads body & signature from PDAs, verifies cipher||kem||nonce||slot_le,
/// then stores ChatMsg with sig_hash for tamper evidence.
pub fn handle_finalize_sig(
    ctx       : Context<FinalizeSig>,
    cipher_len: u32,
    kem_len   : u32,
    nonce     : [u8; 12],
    slot      : u64,
    slh_pub   : [u8; 32],
) -> Result<()> {
    let total = ctx.accounts.buffer.length as usize;
    require!(total <= MAX_CHAT_PAYLOAD, ErrorCode::LenMismatch);

    let proof_len_est = total
        .saturating_sub(cipher_len as usize)
        .saturating_sub(kem_len as usize);
    msg!(
        "DBG step1: slot={} total={} (cipher={} kem={} proof≈{}) need_space={}",
        slot, total, cipher_len, kem_len, proof_len_est,
        8 + CHAT_HEAD + total
    );

    let body = {
        let buf_ai = ctx.accounts.buffer.to_account_info();
        let data   = buf_ai.data.borrow();
        data[BUF_HEAD..BUF_HEAD + total].to_vec()
    };

    let sig_len = ctx.accounts.sigbuf.length as usize;
    // SLH-DSA/SHA2-128s signature is fixed 7,856 bytes; must also fit PDA payload cap.
    require!(sig_len == SIG_BYTES && sig_len <= MAX_SIG_PAYLOAD, ErrorCode::SigFailed);
    let sig = {
        let sig_ai = ctx.accounts.sigbuf.to_account_info();
        let data   = sig_ai.data.borrow();
        data[BUF_HEAD..BUF_HEAD + sig_len].to_vec()
    };

    let blob = [
        &body[..cipher_len as usize + kem_len as usize],
        &nonce,
        &slot.to_le_bytes(),
    ]
    .concat();
    crypto::verify(&blob, &sig, &slh_pub).map_err(|_| ErrorCode::SigFailed)?;

    let chat = &mut ctx.accounts.chat_msg;
    chat.sender     = ctx.accounts.payer.key();
    chat.recipient  = ctx.accounts.recipient.key();
    chat.cipher_len = cipher_len;
    chat.kem_len    = kem_len;
    chat.nonce      = nonce;
    chat.slot       = slot;
    chat.sig_pda    = ctx.accounts.sigbuf.key();
    chat.sig_len    = sig_len as u32;
    chat.sig_hash   = hashv(&[&sig[..]]).to_bytes();
    chat.payload    = body;
    Ok(())
}

/// Accounts for Step 2 (STARK verification).
#[derive(Accounts)]
pub struct VerifyStark<'info> {
    pub chat_msg: Account<'info, ChatMsg>,
}

/// Verifies the STARK proof embedded in ChatMsg.
pub fn handle_verify_stark(ctx: Context<VerifyStark>) -> Result<()> {
    // Sets the heap limit to match the transaction's requestHeapFrame (e.g. 256 KiB).
    #[cfg(all(feature = "custom-heap", any(target_arch = "bpf", target_os = "solana")))]
    { crate::heap::set_heap_limit_bytes(256 * 1024); msg!("DBG Heap: 256KiB"); }

    let chat = &ctx.accounts.chat_msg;
    let cipher_end = chat.cipher_len as usize;
    let total_len = chat.payload.len();
    require!(cipher_end <= total_len, ErrorCode::ProofFailed);

    let off = cipher_end + chat.kem_len as usize;
    require!(off <= total_len, ErrorCode::ProofFailed);

    let proof = &chat.payload[off..];
    let cipher = &chat.payload[..cipher_end];

    msg!("DBG STARK: cipher_len={} kem_len={} proof_len={}",
        chat.cipher_len, chat.kem_len, proof.len());

    let digest = hashv(&[cipher]).to_bytes();
    let mut le0 = [0u8; 8];
    let mut le1 = [0u8; 8];
    le0.copy_from_slice(&digest[0..8]);
    le1.copy_from_slice(&digest[8..16]);
    let seed = u64::from_le_bytes(le0);
    let inc = u64::from_le_bytes(le1);

    crate::crypto::verify_stark(proof, seed, inc)
        .map_err(|_| ErrorCode::ProofFailed)?;
    Ok(())
}
