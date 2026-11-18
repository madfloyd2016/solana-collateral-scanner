# yDelta fixed-rate identity regression plan

This is a test specification, not an executable harness. Adapt it to the exact yDelta instruction account layouts and run only in a local validator / LiteSVM / Mollusk environment with synthetic accounts. Do not submit production transactions.

| # | Scenario | Mutation | Expected result |
|---|---|---|---|
| 1 | Valid baseline | Correct debt/collateral banks, market mints, vaults, oracle and seat balance | Accept; shares and loan accounting match the intended assets |
| 2 | Wrong user token mint | Supply a token account whose Mint differs from the Market collateral Mint | Reject; no collateral credit or borrow-capacity increase |
| 3 | Wrong vault mint | Substitute a vault token account holding another Mint | Reject before crediting or transferring |
| 4 | Wrong bank / group / marginfi account | Substitute an account not matching the Market-stored relationship | Reject; no state change |
| 5 | Wrong oracle | Supply an oracle account other than the Bank `primary_oracle` | Reject; no valuation or loan state change |
| 6 | Decimal / share-price boundary | Use mismatched mint decimals or manipulated/invalid share-price fixture | Reject or calculate from the validated Bank/Mint values; never inflate collateral value |
| 7 | Insufficient seat balance / failed transfer | Pledge more collateral than withdrawable balance, or force transfer failure | Reject atomically; seat balance, shares, collateral value and borrow capacity unchanged |

## Additional path-specific tests (not counted in the seven above)

- Withdraw / redeem: verify destination Mint, vault Mint, share burn, amount-out and state updates are consistent and atomic.
- P2Pool fallback: verify Marginfi health, bank/group identity, collateral/debt mapping and conversion back to fixed-rate debt.
- Liquidation / maturity settlement: verify the same asset identity, decimals, oracle and recorded LTV thresholds are used.
- Token-2022 extension rejection: verify market creation rejects unsupported PermanentDelegate / TransferHook mints, and test all accepted extensions separately.

## Assertions

For every rejected case, assert the error and compare pre/post account state. At minimum: user seat balances, collateral shares, vault token balances, market/loan state, borrow capacity and any queued match records. A returned error without state assertions is insufficient to prove atomic rollback.
