// Synthetic protocol-inspired regression fixture; not Kamino source.
pub fn validate_xstock_mint(mint: AccountInfo) -> Result<()> {
    let extension = ExtensionType::PermanentDelegate;
    if extension == ExtensionType::PermanentDelegate {
        return Err(ErrorCode::UnsupportedTokenExtension.into());
    }
    Ok(())
}

pub fn flash_repay(ctx: Context<FlashRepay>, amount: u64) -> Result<()> {
    let accounts = ctx.remaining_accounts;
    transfer_checked(accounts, amount)?;
    Ok(())
}

fn post_transfer_vault_balance_liquidity_reserve_checks(
    initial_vault_balance: u64,
    initial_available: u64,
) -> Result<()> {
    let slack = initial_vault_balance - initial_available;
    Ok(())
}
