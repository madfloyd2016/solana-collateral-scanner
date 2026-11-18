// Synthetic training fixture only. It is not protocol source code.
pub fn deposit_collateral(
    token_program: AccountInfo,
    user_token: AccountInfo,
    vault_token: AccountInfo,
    asset_id: u16,
    amount: u64,
    remaining_accounts: &[AccountInfo],
) -> Result<()> {
    token::transfer_checked(user_token, vault_token, amount)?;
    let config = load_asset_config(asset_id)?;
    let oracle = remaining_accounts.get(0).ok_or(ErrorCode::MissingOracle)?;
    let raw_value = amount / 10u64.pow(config.decimals as u32);
    let price = read_oracle_price(oracle)?;
    update_collateral_value(raw_value * price)
}
