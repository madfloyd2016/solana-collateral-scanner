// Synthetic protocol-inspired negative regression fixture; not Marginfi source.
#[derive(Accounts)]
pub struct MarginfiLikeDeposit<'info> {
    #[account(token::mint = liquidity_mint)]
    pub source_token_account: InterfaceAccount<'info, TokenAccount>,
    #[account(has_one = liquidity_mint)]
    pub bank: Account<'info, Bank>,
    pub liquidity_mint: InterfaceAccount<'info, Mint>,
}

pub fn deposit(ctx: Context<MarginfiLikeDeposit>, amount: u64) -> Result<()> {
    let bank = ctx.accounts.bank;
    let config_mint = bank.liquidity_mint;
    let decimals = bank.liquidity_mint_decimals;
    let price = read_oracle_price(ctx.accounts.oracle)?;
    let value = amount * price / 10u64.pow(decimals as u32);
    update_borrow_capacity(value);
    Ok(())
}
