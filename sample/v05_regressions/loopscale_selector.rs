// Synthetic protocol-inspired regression fixture; not Loopscale source.
pub fn deposit(asset_id: u16, source_token_account: AccountInfo, amount: u64) -> Result<()> {
    let selected_reserve = reserves[asset_id as usize];
    let config_mint = selected_reserve.collateral_mint;
    let decimals = selected_reserve.collateral_decimals;
    let price = read_oracle_price(selected_reserve.oracle)?;
    let value = amount * price / 10u64.pow(decimals as u32);
    update_borrow_capacity(value);
    Ok(())
}
