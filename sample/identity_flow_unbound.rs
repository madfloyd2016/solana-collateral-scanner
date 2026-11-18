// Synthetic v0.4 regression fixture. Not source code from any real protocol.
// The function reads the actual token-account Mint and a selected config Mint,
// then uses config-derived decimals and oracle price without a visible equality
// guard in this analyzed source scope. This is a review lead, not a real exploit.
pub fn deposit_unbound_review(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let source_mint = ctx.accounts.user_token_account.mint;
    let market = ctx.accounts.market;
    let selected_config_mint = market.collateral_mint;

    let decimals = market.collateral_mint_decimals;
    let price = read_oracle_price(ctx.accounts.oracle)?;
    let value = amount * price / 10u64.pow(decimals as u32);
    update_borrow_capacity(value);
    let _observed_mint = source_mint;
    let _observed_config_mint = selected_config_mint;
    Ok(())
}
