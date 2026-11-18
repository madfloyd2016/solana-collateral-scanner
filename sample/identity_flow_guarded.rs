// Synthetic v0.4 regression fixture. Not source code from any real protocol.
// The source token account Mint is compared with the Market's collateral Mint
// in a helper, and config-derived decimals/oracle price flow to a borrow sink.
pub fn deposit_guarded(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let source_account = ctx.accounts.user_token_account;
    let market = ctx.accounts.market;
    validate_collateral_identity(source_account, market)?;

    let decimals = market.collateral_mint_decimals;
    let price = read_oracle_price(ctx.accounts.oracle)?;
    let value = amount * price / 10u64.pow(decimals as u32);
    update_borrow_capacity(value);
    Ok(())
}

fn validate_collateral_identity(
    source: Account<TokenAccount>,
    market: Account<Market>,
) -> Result<()> {
    let actual_mint = source.mint;
    let expected_mint = market.collateral_mint;
    require_keys_eq!(actual_mint, expected_mint);
    Ok(())
}
