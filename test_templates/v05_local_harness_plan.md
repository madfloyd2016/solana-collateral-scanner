# v0.5 protocol-specific local harness plan

Purpose: turn a static review lead into a reproducible local invariant test without
sending transactions to a production protocol or using third-party funds.

## Required inputs

- Exact source repository and commit SHA.
- Program ID and recorded deployment slot, if comparing with mainnet.
- Verifiable-build evidence or an explicit statement that source/deployment equivalence is unknown.
- Real instruction account layout, PDA seeds, instruction discriminator, and account serialization.
- A local-only runtime such as LiteSVM or Mollusk.
- Synthetic keypairs, token accounts, Mints, or a sanitized one-slot snapshot.

## Core identity test matrix

| Case | Setup | Expected local result |
|---|---|---|
| Valid identity | Mint A + Config A + Oracle A | Instruction succeeds and accounting changes by the expected amount |
| Wrong collateral Mint | Mint A + Config B | Rejected before collateral credit or borrow-capacity update |
| Wrong oracle | Config A + Oracle B | Rejected before valuation is accepted |
| Decimal mismatch | Mint A decimals differ from Config B decimals | Wrong unit normalization is rejected or impossible by construction |
| Wrong selector | Numeric selector selects a config for a different Mint | Rejected before value reaches health/LTV/borrow capacity |
| Failed transfer | Token CPI fails after preliminary checks | All relevant state changes roll back atomically |

## Token-2022 authority and extension tests

- Build Mints with and without `PermanentDelegate`, `TransferHook`, `Pausable`, `DefaultAccountState`, and other supported extensions.
- Confirm which extensions the protocol explicitly rejects, accepts, or ignores.
- If a privileged authority can debit or freeze a protocol vault, verify the protocol's internal accounting remains consistent or the relevant operation fails safely.
- Do not infer risk solely from extension presence; test the authority, actual vault reachability, and accounting behavior.

## Arithmetic and accounting tests

- Exercise boundary values around `vault_balance == total_available_amount`.
- Test one-atom deficits, exact-balance states, and any permitted slack.
- Verify subtraction and multiplication failures are checked and return a controlled error rather than silently wrapping or corrupting state.
- Confirm failed instructions are atomic and do not leave partial accounting updates.

## Flash-repay tests

- Verify the borrowed Mint, repayment Mint, reserve/config, vault, token program, and authority all refer to the expected assets/accounts.
- Verify repayment amount conservation, fee handling, and minimum repayment constraints.
- Test wrong-Mint, wrong-reserve, wrong-vault, and insufficient-repayment cases.
- Verify the flash-loan obligation is closed only after the correct repayment is observed.

## Acceptance criteria

- Each negative case fails for the intended invariant, not because the harness is malformed.
- Each valid case succeeds.
- State diffs are captured before and after each instruction.
- The harness records program binary hash, source commit, snapshot slot, and runtime version.
- Mainnet source/deployment equivalence is stated separately; a local harness result alone does not prove it.

This is a test plan, not a ready-made harness. Each protocol needs its own instruction builder and exact account fixtures.
