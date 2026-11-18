# LiteSVM / Mollusk local test plan: collateral identity invariants

This is a protocol-adaptation checklist, not a ready-to-run exploit harness. Deploy only the exact program build to a local VM and use synthetic mints, token accounts, and oracle fixtures.

## Test matrix

| Case | Supplied mint | Selected config | Oracle | Expected result |
|---|---|---|---|---|
| Valid baseline | Mint A | Config A | Oracle A | Accept; credit correct value |
| Cross-asset mismatch | Mint A | Config B | Oracle B | Reject before crediting collateral |
| Wrong oracle | Mint A | Config A | Oracle B | Reject |
| Decimal mismatch | Mint A (9) | Config B (8) | Oracle A | Reject or normalize from the validated Mint; never inflate value |
| Wrong vault mint | Mint A | Config A | Oracle A; vault holds Mint B | Reject |
| Failed transfer | Mint A | Config A | Oracle A | No collateral credit and no borrow-capacity increase |

## Invariants

1. `user_token_account.mint == collateral_config.mint`.
2. `vault_token_account.mint == collateral_config.mint`.
3. The oracle account/feed identity is the one configured for that collateral asset.
4. Decimal normalization is derived from the validated Mint or an immutable config proven equal to it.
5. A rejected deposit leaves collateral shares, collateral value, health, and borrow capacity unchanged.
6. The borrow limit is computed from the same asset identity that was actually transferred into custody.

## Harness adaptation

- Load the exact program binary into LiteSVM or Mollusk.
- Create two synthetic SPL mints with different decimals (for example 8 and 9).
- Create independent config PDAs and oracle fixtures for each mint.
- Build the valid baseline instruction using the protocol's real account order and discriminators.
- Mutate exactly one account or config selector per negative test.
- Assert both the returned error and all relevant post-state balances / collateral / borrow-limit values.
- Never point the harness at a production RPC for transaction submission.
