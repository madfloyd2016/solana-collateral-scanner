# HIGH_REVIEW: deposit_collateral

- File: `sample/loopscale_like.rs`
- Line: `2`
- Score: `13`
- Signals: `financial,asset_selector,token_transfer,oracle_price,decimals_scale,dynamic_accounts,config_reference`

## Why this was flagged

asset/config selector appears in the instruction call graph; SPL token movement appears in the instruction call graph; oracle/price handling appears in the instruction call graph; decimal or unit scaling appears in the instruction call graph; dynamic or loosely typed account access appears in the call graph; no mint-to-config binding pattern found in the reachable functions; this is not proof of absence; no obvious oracle-to-config binding pattern found in the reachable functions

## Related functions

```json
[{"function": "deposit_collateral", "file": "sample/loopscale_like.rs", "line": 2, "signals": ["financial", "asset_selector", "token_transfer", "oracle_price", "decimals_scale", "dynamic_accounts", "config_reference"]}]
```

## Source snippet

```rust
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
```

## Required manual checks

1. Identify the exact SPL Mint for the user source account and vault destination account.
2. Trace the selected collateral/reserve config PDA and prove it is bound to that Mint.
3. Verify the oracle account owner, feed identity, and config-to-oracle binding.
4. Compare Mint decimals with every decimal value used in normalization.
5. Trace the calculated value into health, LTV, and borrow capacity.
6. Match this source commit to the deployed program binary before making a mainnet claim.

## Local-only invariant tests

- Valid Mint A + Config A + Oracle A should succeed.
- Mint A + Config B should be rejected before collateral value is credited.
- Mint A with a different-decimals Config B must not change the credited value.
- Oracle B supplied for Config A must be rejected.
- A failed deposit must leave collateral and borrow capacity unchanged.

This is a static-review lead, not a confirmed vulnerability. Do not test against live user funds.