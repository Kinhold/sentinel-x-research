use anchor_lang::prelude::*;

#[program]
pub mod sentinel_safe {
    use super::*;

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        require!(ctx.accounts.from.is_signer);
        require_keys_eq!(*ctx.accounts.external_program.owner, system_program::ID);
        let cpi_program = ctx.accounts.external_program.to_account_info();
        anchor_lang::solana_program::program::invoke(
            &anchor_lang::solana_program::system_instruction::transfer(
                &ctx.accounts.from.key(),
                &ctx.accounts.to.key(),
                amount,
            ),
            &[ctx.accounts.from.to_account_info(), ctx.accounts.to.to_account_info()],
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Signer<'info>,
    /// CHECK: destination
    #[account(mut)]
    pub to: AccountInfo<'info>,
    /// CHECK: owner-checked above
    pub external_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
}
