// Synthetic protocol-inspired negative regression fixture; not yDelta source.
#[derive(Accounts)]
pub struct YDeltaLikeDeposit<'info> {
    #[account(constraint = user_token_account.mint == market.collateral_mint)]
    pub user_token_account: Account<'info, TokenAccount>,
    pub market: Account<'info, Market>,
    pub oracle: AccountInfo<'info>,
}

pub fn deposit(ctx: Context<YDeltaLikeDeposit>, amount: u64) -> Result<()> {
    let market = ctx.accounts.market;
    let config_mint = market.collateral_mint;
    let decimals = market.collateral_mint_decimals;
    let price = read_oracle_price(ctx.accounts.oracle)?;
    let value = amount * price / 10u64.pow(decimals as u32);
    update_borrow_capacity(value);
    Ok(())
}
