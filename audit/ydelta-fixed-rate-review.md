# yDelta fixed-rate path review record (carried into v0.4.0)

Status: **partial manual review; no A-to-B collateral identity path reported in the reviewed fixed-rate flow**. This record captures user-supplied review notes; the scanner has not independently verified the repository or reproduced the analysis.

Program ID: `HfYCWUgFuUbuzZTeQAAGzVkXw2uFM51QRoDfhFV8vyCj`  
Repository: https://github.com/IMEF-FEMI/yDelta

## Reviewed claims

1. **Market creation:** `CreateMarketContext` reportedly requires debt/collateral bank mints to equal the market-declared mints. `MarketFixed` decimals are reportedly read from the real mints at creation.
2. **Deposit:** `DepositContext` reportedly reads the user token account mint and compares it with the market debt/collateral mint; debt-asset direct deposits are rejected. Vault, bank, marginfi and group accounts are reportedly tied to market-stored values. Credited amount is reportedly derived from vault balance delta.
3. **Bid:** `collateral_atoms` is reportedly converted using the collateral bank share price and debited from the seat's withdrawable balance; un-deposited collateral cannot be pledged.
4. **Match / liquidation gates:** LTV reportedly uses stored decimals, sub-vault `max_ltv_bps`, and a bank-anchored oracle. `read_oracle_price` reportedly requires the supplied oracle key to equal the bank's `primary_oracle`. LTV math reportedly fails closed for zero price/weight/limits.
5. **Token-2022 extensions:** market creation reportedly rejects mints with PermanentDelegate and TransferHook extensions. This is a reported restriction, not a general proof that every Token-2022 extension path is safe.
6. **Hygiene note:** `DepositContext` reportedly accepts a separate `mint` account without directly checking its key against the market mint. User review indicates Token-2022 `transfer_checked` checks the mint and SPL path does not use this account. Retain as low-priority review item; no exploitability established.

## Explicitly incomplete

- Withdraw / redeem path has not been reviewed line by line.
- P2Pool fallback health checks primarily rely on Marginfi and need separate tracing.
- Liquidation and settlement paths need complete account/value-flow review.
- Seven local negative/positive invariant tests have not yet been implemented or run.
- Source commit to deployed binary equivalence has not been established here.

## Classification

Use as a **negative regression reference only for the reviewed fixed-rate path**. Do not mark the whole program `safe`, `validated`, or `confirmed`. The review is not proof that yDelta has no other vulnerability.


## v0.4 regression handling

- The v0.4 suite includes a **synthetic yDelta-style guarded-path pattern test** to check that a visible actual-Mint/config-Mint equality guard is not automatically reported as an unbound identity flow.
- That fixture is authored for regression testing and is not copied from yDelta source.
- The scanner has not independently fetched, built, executed, or matched yDelta source to the deployed binary as part of this package build.
- Withdraw/Redeem, P2Pool, liquidation/settlement and the seven protocol-specific local invariant tests remain incomplete as recorded above.
