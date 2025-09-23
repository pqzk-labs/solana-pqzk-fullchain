//! Initialization of PDA buffers (buf, sig).
//!
//! InitBuffer / handle_init_buffer: prepares the body buffer at a fixed size.
//! InitSignature / handle_init_signature: prepares the signature buffer keyed by (sender, recipient, slot).

use anchor_lang::prelude::*;
use crate::state::{BufferPda, BUF_ACCOUNT_SPACE};

/// Accounts for initializing the body buffer PDA.
#[derive(Accounts)]
pub struct InitBuffer<'info> {
    #[account(
        init_if_needed, payer=payer, space=BUF_ACCOUNT_SPACE, // Always 10,232 bytes
        seeds=[b"buf", payer.key().as_ref()], bump
    )]
    pub buffer: Account<'info, BufferPda>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Resets length and sha_chain of the body buffer.
pub fn handle_init_buffer(ctx: Context<InitBuffer>) -> Result<()> {
    let buf = &mut ctx.accounts.buffer;
    buf.sender    = ctx.accounts.payer.key();
    buf.length    = 0;
    buf.sha_chain = [0u8; 32];
    Ok(())
}

/// Accounts for initializing the signature buffer PDA.
#[derive(Accounts)]
#[instruction(recipient: Pubkey, slot: u64)]
pub struct InitSignature<'info> {
    #[account(
        init_if_needed, payer=payer, space=BUF_ACCOUNT_SPACE,
        seeds=[b"sig", payer.key().as_ref(), recipient.key().as_ref(), &slot.to_le_bytes()], bump
    )]
    pub buffer: Account<'info, BufferPda>,

    /// CHECK: Used only for PDA seeds.
    pub recipient: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// Resets length and sha_chain of the signature buffer.
pub fn handle_init_signature(
    ctx: Context<InitSignature>,
    _recipient: Pubkey,
    _slot: u64,
) -> Result<()> {
    let buf = &mut ctx.accounts.buffer;
    buf.sender    = ctx.accounts.payer.key();
    buf.length    = 0;
    buf.sha_chain = [0u8; 32];
    Ok(())
}
