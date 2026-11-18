# Solana Collateral Identity Scanner v0.5.0

**Release title:** `v0.5.0 — Protocol-aware analysis`

**Release date recorded by the source project:** 2026-11-06

## Overview

This cumulative release adds protocol-aware review signals to the existing Solana DeFi source scanner. It retains the v0.2/v0.3 scanning and discovery workflows and the v0.4 asset-identity dataflow pass.

## Highlights

- Structured, best-effort extraction of Anchor `#[derive(Accounts)]` and field-level `#[account(...)]` constraints.
- Asset-identity review across token-account Mint, market/reserve configuration, oracle, decimals, valuation, health/LTV, and borrow-capacity paths.
- Token-2022 extension-policy review signals.
- Financial arithmetic review leads and `*_checks` helper roots.
- Numeric/untyped asset-selector flow review.
- Dedicated `flash_repay` account-flow coverage markers.
- JSON, CSV, and Markdown review outputs while preserving the earlier report formats and CLI options.
- Synthetic protocol-inspired regression fixtures for selector, extension/arithmetic, and Anchor-binding patterns.

## Verification

The original v0.5.0 source archive was checked against SHA-256:

`8f1aa466565281d0b4e0faca80aa52af880625a781718608a1ea31746a4404f9`

Repository preparation on 2026-11-18 reran the unit suite: **53 tests passed**. A synthetic-fixture smoke scan completed and generated review outputs.

## Important limitations

- Static findings are review leads, not confirmed vulnerabilities.
- Protocol-inspired fixtures are synthetic and are not production source code from the named protocols.
- This release does not establish source-to-binary equivalence or prove that a repository matches a deployed program.
- The analyzer is heuristic; it is not compiler-grade Rust MIR/SSA analysis.
- The project does not submit transactions or test against production user funds.

See [README.md](../README.md), [Research Scope](RESEARCH_SCOPE.md), and [Security Policy](../SECURITY.md) for usage boundaries and known limitations.
