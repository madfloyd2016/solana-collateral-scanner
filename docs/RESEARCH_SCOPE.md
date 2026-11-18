# Research Scope and Safety Boundaries

## Purpose

Solana Collateral Identity Scanner is a read-only research tool for source-level triage of Solana DeFi lending, collateral, reserve, vault, margin, and Token-2022 code paths.

Its main research question is whether the asset identity used for valuation and risk calculations remains consistently bound across the following chain:

`Token Account Mint -> Market / Reserve / Collateral Config -> Oracle -> Decimals -> Collateral Value -> Health / LTV -> Borrow Capacity`

It also surfaces review leads involving Token-2022 authorities and extensions, vault accounting, arithmetic boundaries, and flash-repay account flows.

## Permitted use

- Analyze source code that you own or are expressly authorized to assess.
- Use public source repositories only within applicable terms, program rules, and coordinated-disclosure requirements.
- Use public RPC methods for read-only account and deployment metadata collection.
- Validate hypotheses with synthetic fixtures or isolated local test environments.
- Keep a record of source commit, scan time, program ID, cluster, and evidence provenance.

## Out of scope

- Signing or submitting transactions.
- Borrowing, liquidating, transferring tokens, or changing production state.
- Testing with third-party funds or user accounts.
- Treating GitHub repository discovery, IDL availability, or an executable Program account as proof that a repository matches a deployed binary.
- Treating static pattern matches or synthetic regression tests as confirmed vulnerabilities.

## Evidence levels

Interpret scanner output conservatively:

- `signal`: a static pattern was detected.
- `candidate`: manual review indicates a plausible path worth validating.
- `validated`: an isolated local harness demonstrates an invariant violation.
- `confirmed`: source, deployed version, impact, and reproducible evidence have been independently established.
- `insufficient_evidence`: the analyzed source did not provide enough evidence; this is not a safety verdict.
- `negative_regression`: a specific synthetic safe-pattern test did not trigger the targeted finding; this is not a whole-program security verdict.

The current v0.5.0 implementation primarily produces static signals and review leads. It does not implement compiler-grade Rust MIR/SSA analysis or source-to-binary verification.

## Target-list interpretation

`targets.json` is a curated research queue. Its priority labels are scheduling hints only; they are not severity ratings, vulnerability claims, or confirmation that a target is affected. Repository URLs are candidates that must be checked against the exact deployed program before findings are attributed to mainnet.
