# Changelog

## v0.5.0 - 2026-11-06

- Cumulative release: includes the planned v0.4.1 detection-calibration fixes; no separate v0.4.1 ZIP is required.
- Added `protocol_analysis.py` for structured Anchor account-field and `#[account(...)]` constraint parsing, including Mint and oracle identity chains.
- Added Token-2022 extension policy signals for privileged and accounting-relevant extensions.
- Added financial arithmetic review for unchecked subtraction and checked, saturating, wrapping, and overflowing operations.
- Added `*_checks` helpers as dataflow roots when they operate on financial/accounting state.
- Added numeric and untyped asset-selector provenance through simple indexed config selection and recognized value/borrow sinks.
- Added a dedicated `flash_repay` account-flow coverage marker.
- Added synthetic protocol-inspired regression fixtures for Loopscale, Kamino, Marginfi, and yDelta patterns; these are not production source or deployment validation.
- Added `protocol_analysis.json`, `.csv`, and Markdown review outputs; preserved legacy reports and CLI behavior.
- Added `--no-protocol-analysis`; `--no-dataflow` remains independent.
- Added a low-severity hygiene lead for Anchor Mint account fields without a recognized local binding.
- Added checked-arithmetic fallback semantics, overflowing-operation, bare multiplication/addition, and numeric-literal subtraction review patterns.
- Added PDA seed/bump and owner attribute evidence to the Anchor context map, including contexts with `#[instruction(...)]`.
- Added a local-only LiteSVM/Mollusk harness plan; it is a template, not a runnable protocol harness.
- Full local test suite: 53 tests passing.
- No real mainnet vulnerability claim is made by these static rules.


## v0.4.0 - 2026-11-06

- Added `identity_dataflow.py`: source-level assignment/provenance tracking for actual token-account Mint, config/reserve/market Mint, config objects, oracle accounts/prices, decimals and amount inputs.
- Added conservative same-file helper argument-to-parameter propagation and common helper return-expression summaries, bounded by `--max-depth`.
- Added actual-Mint-to-config-Mint and oracle-account-to-config-oracle comparison pattern detection.
- Added valuation, health, borrow-capacity, liquidation and withdraw/redeem sink summaries showing which provenance labels reach each sink.
- Added cross-instruction state-field reference mapping for struct fields written by one function and read by another.
- Added separate `identity_dataflow.json`, `identity_dataflow.csv` and `identity_dataflow_review/` outputs; existing `findings.json`, `findings.csv` and `review/` outputs remain intact.
- Enabled the v0.4 dataflow pass by default; added `--no-dataflow` and `--version` options.
- Updated discovery user-agent/version metadata to v0.4.0 without changing discovery behavior.
- Added two synthetic identity-flow fixtures and 16 dataflow regression tests. Combined local test suite: 34 tests passing.
- Explicitly retained yDelta as a partial user-supplied negative regression reference. Synthetic tests do not independently validate yDelta source or deployed program.

## v0.3.1 - 2026-11-06

- Added identity-assessment metadata to Rust heuristic findings: binding-patterns-present, missing-pattern review flags, and explicit limitations. These are triage hints, not security verdicts.
- Added conservative GitHub repository-role hints (`research_poc`, `audit`, `sdk_or_client`, `unverified_repository_candidate`); discovery never auto-claims a repository is official deployed source.
- Added regression coverage for repository-role classification and identity-assessment output.
- Added yDelta as a curated Solana target with its repository role and explicit partial-review caveats.
- Added a yDelta fixed-rate review record based on user-supplied code-review notes; Withdraw/Redeem, P2Pool, liquidation details, source/deployment equivalence and local validation remain incomplete.
- Added a seven-case local regression test specification for yDelta. The specification is not an executable protocol harness and has not been run against yDelta.
- Preserved the v0.3 discovery CLI and v0.2 scanner CLI compatibility.

## v0.3.0 - 2026-11-06

- Added independent `discover.py` discovery pipeline; existing `scanner.py` CLI and report formats remain unchanged.
- Added DeFiLlama Solana protocol discovery and GitHub repository discovery for Rust-based Solana lending/collateral projects.
- Added normalized candidate schema, source evidence, source deduplication, score/reasons, confidence and priority.
- Added Solana base58/public-key length validation and read-only `getAccountInfo` RPC validation (existence, executable flag, owner).
- Added GitHub default-branch commit SHA lookup; explicitly does not claim source-to-deployment equivalence.
- Added disk cache, TTL, timeout, request spacing, source-failure capture, CSV/JSON reports and v0.2-compatible targets export.
- Added optional handoff to the existing scanner via `--scan`.
- Added discovery unit tests. Combined test suite: 15 tests passing.

## v0.2.0
- See the original v0.2 baseline implementation and README.
