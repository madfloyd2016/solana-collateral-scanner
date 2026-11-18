# v0.4 Asset Identity Dataflow: Manual Validation Plan

This plan turns a static dataflow review lead into a protocol-specific local test. It is not an exploit recipe and must not be run against production user funds.

## 1. Pin the source being reviewed

- Record repository URL, branch, exact commit SHA and working-tree status.
- Record the target Program ID, cluster, executable status, deployment slot and ProgramData hash where available.
- Do not treat a ProgramData hash as source-to-binary verification. Use a verifiable build or other authoritative deployment mapping before attributing findings to mainnet.

## 2. Validate the actual token identity

- Identify the instruction's user/source Token Account.
- Read the Token Account owner and Mint from the account data using the correct SPL Token or Token-2022 layout.
- Identify the destination vault Token Account and independently confirm its Mint.
- Trace the actual transfer instruction and confirm the token program, source, destination, authority and Mint arguments.

## 3. Validate the selected configuration

- Identify the argument, index, PDA seeds or account key selecting the Market/Reserve/Collateral Config.
- Decode the exact config account with the protocol's real layout.
- Identify the config's debt Mint, collateral Mint, vault, bank and group references.
- Prove that the runtime instruction checks the selected config's Mint against the actual source/destination Mint before crediting state.
- Check whether the guard is on every reachable path, not merely present in a helper or account struct.

## 4. Validate valuation provenance

- Identify the exact oracle account/feed and verify owner, feed identity, market and config binding.
- Identify where decimals originate: validated Mint, stored config, bank metadata or caller-supplied data.
- Trace amount, price and decimals through normalization into collateral value, shares, health, LTV and borrow capacity.
- Check integer rounding, truncation, overflow/underflow, zero values and unit conversions.

## 5. Validate cross-instruction state

- Use `identity_dataflow.json`'s `cross_instruction_state_field_links` as a field-navigation aid.
- Confirm the writer and reader operate on the same intended PDA/account type and validate its key/seeds/owner.
- Check whether any instruction can overwrite, stale, desynchronize or reinterpret Mint, oracle, decimals, LTV, shares or accounting fields.
- Confirm withdraw, redeem, liquidation, repayment and maturity settlement preserve the same asset identity assumptions.

## 6. Build a local-only harness

Use the protocol's exact account layouts, PDA derivations and instruction builders in LiteSVM, Mollusk or a local validator. Use synthetic keypairs and synthetic balances only.

Minimum scenarios:

1. Valid Mint A + Config A + Oracle A succeeds.
2. Mint A + Config B is rejected before collateral credit or borrow-capacity change.
3. Wrong vault Mint is rejected atomically.
4. Oracle B supplied for Config A is rejected.
5. Decimal mismatch cannot inflate collateral value.
6. Insufficient shares/seat balance cannot create collateral credit.
7. A failed CPI/transfer leaves all relevant state unchanged.

For every rejected scenario, compare pre/post token balances, shares, seat/obligation state, vault accounting, market state and borrow capacity.

## 7. Interpret the scanner correctly

- `binding_guard_and_config_value_flow_observed_manual_validation_required` means a recognizable comparison pattern was found, not that the guard is complete or dominates all sinks.
- `potential_unbound_mint_to_config_value_flow_review_required` means no matching guard was found in the analyzed scope, not that a working exploit exists.
- `insufficient_identity_dataflow_evidence` is inconclusive, not safe.
- The state-field map is based on struct/field names and does not prove account identity or value continuity.
