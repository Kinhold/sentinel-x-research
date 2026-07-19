use anchor_lang::prelude::*;

#[program]
pub mod sentinel_fixture {
    use super::*;

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
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
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Signer<'info>,
    /// CHECK: demo fixture
    pub to: AccountInfo<'info>,
    /// CHECK: demo fixture
    pub external_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(init)]
    pub vault: Account<'info, Vault>,
}

#[account]
pub struct Vault {}
