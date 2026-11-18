# Solana Collateral Identity Scanner v0.5.0

**Maintainer:** [@madfloyd2016](https://github.com/madfloyd2016)  
**License:** [MIT](LICENSE)  
**Release:** `0.5.0` · **Release date:** 2026-11-06 · **Scope:** Solana mainnet / Solana DeFi source code

A read-only research tool for triaging asset-identity, collateral valuation, Token-2022 authority, vault-accounting, arithmetic, and flash-repay code paths in Solana DeFi programs.

> **Research and safety boundary:** This project performs source-level static analysis and read-only metadata discovery. It does not sign or submit transactions, move funds, or exploit live programs. Findings are review leads, not confirmed vulnerabilities. Use it only on code and systems you own or are expressly authorized to assess.

The v0.5.0 source archive used for this repository was integrity-checked against SHA-256 `8f1aa466565281d0b4e0faca80aa52af880625a781718608a1ea31746a4404f9`. The full unit suite was rerun during repository preparation on 2026-11-18: **53 tests passed**.

See [Research Scope](docs/RESEARCH_SCOPE.md), [Security Policy](SECURITY.md), and [Contributing](CONTRIBUTING.md).

## v0.5.0: protocol-aware analysis (cumulative release)

v0.5.0 includes the v0.4.1 detection-calibration work and builds on the v0.4.0 baseline. There is no separate v0.4.1 release artifact: the following fixes are included in this cumulative version.

### Included v0.4.1 calibration fixes

- Structured parsing of Anchor `#[derive(Accounts)]` structs and field-level `#[account(...)]` constraints. The parser links `Context<T>` handlers to fields and records `has_one`, `constraint`, `token::mint`, `associated_token::mint`, `address`, `owner`, `seeds`, and `bump` evidence.
- Identity guard recognition includes multi-edge Anchor relationships, such as a token account constrained to a Mint account and a config account `has_one`-bound to that same Mint account.
- Token-2022 extension policy signals for `PermanentDelegate`, `TransferHook`, `Pausable`, `DefaultAccountState`, `MintCloseAuthority`, confidential-transfer, scaled-UI, transfer-fee, and related extensions. An extension mention is a review lead, not an automatic vulnerability.
- Financial arithmetic review for naked subtraction and explicit checked, saturating, wrapping, and overflowing arithmetic methods.
- Functions named like `*_checks` are eligible dataflow roots when their names or bodies indicate balance, liquidity, reserve, vault, collateral, token, or debt logic.
- Numeric and untyped asset selectors (for example `asset_id`, `reserve_index`, and `market_idx`) are tracked through simple indexed config selection and into recognized value/borrow sinks.
- `flash_repay` functions receive a dedicated account-identity and balance-conservation review marker.
- The legacy static scanner attaches structured Anchor constraint evidence to findings, reducing cases where a binding in the `Accounts` struct is invisible to the handler-level heuristic.
- A Mint account field with no recognized local Anchor address/equality/config binding receives a separate `LOW_REVIEW` hygiene lead; this does not override handler-side checks or SPL Token CPI semantics.

### Protocol-aware outputs

The default scan now writes three complementary report families:

- `findings.json` / `findings.csv` / `review/`: legacy v0.2/v0.3 signal aggregation, retained for compatibility.
- `identity_dataflow.json` / `.csv` / `identity_dataflow_review/`: assignment provenance, helper propagation, selector-to-config flow, financial sinks, and cross-instruction state-field links.
- `protocol_analysis.json` / `.csv` / `protocol_analysis_review/`: structured Anchor account maps, Token-2022 extension policy signals, financial arithmetic review leads, and flash-repay coverage markers.

Use `--no-protocol-analysis` to disable the v0.5 protocol-aware pass. Use `--no-dataflow` to disable the identity dataflow pass. These switches are independent.

### Synthetic protocol-inspired regression fixtures

The directory `sample/v05_regressions/` contains **synthetic protocol-inspired fixtures** for four regression roles:

- `loopscale_selector.rs`: untyped asset selector reaching a selected reserve and value sink; expected to create a high-priority review lead.
- `kamino_extension_arithmetic.rs`: Token-2022 extension policy, flash-repay coverage, and financial subtraction review patterns.
- `marginfi_anchor_bound.rs`: a negative identity-confusion fixture where Anchor `token::mint` plus config `has_one` binds the token Mint.
- `ydelta_anchor_bound.rs`: a negative identity-confusion fixture with a direct Anchor token-account-Mint-to-market-Mint constraint.

These are **not** source files from Loopscale, Kamino, Marginfi, or yDelta. They are regression patterns based on the supplied audit summary. Passing these tests does not mean those production protocols have been re-scanned, their deployed binaries matched, or any finding independently reproduced.

### v0.5 status semantics and limits

- `untyped_asset_selector_to_config_value_flow_review_required` means a numeric/loosely typed selector appears to select configuration that reaches a recognized sink without a recognized Mint-binding guard in the analyzed scope. It is a review lead, not proof of A-to-B asset confusion.
- Anchor constraint maps show syntactic relationships in attributes. They do not prove macro expansion, runtime execution order, same-account identity across instructions, or source-to-binary equivalence.
- Arithmetic findings identify operations requiring review; they do not prove that an underflow/overflow state is reachable or exploitable.
- Token-2022 extension findings identify extension names and local policy signals; they do not prove an extension is present on a live Mint or that an authority can exercise it.
- `flash_repay` findings are coverage markers only. The exact repayment/config/account gap must be established from the implementation and a local harness.
- `anchor_unchecked_mint_account_key_review` is a low-severity hygiene lead for a Mint account field without a recognized local Anchor binding; handler/helper validation and Token Program instruction semantics may enforce the relationship elsewhere.
- Rust traits, macros, dynamic dispatch, generated code, cross-crate aliasing, CPI behavior, complex PDA derivations, and compiler-level dataflow remain outside this heuristic analyzer.

### v0.5 quick start

```bash
python3 -m unittest discover -s tests -v
python3 scanner.py --root sample --out reports-v05
```

For a protocol-specific local validation design, see `test_templates/v05_local_harness_plan.md`. The plan is not a runnable LiteSVM/Mollusk harness; each protocol still needs its exact instruction builder, account layout, PDA derivations, and fixture state. See `audit/v0.5-regression-coverage.md` for the four synthetic regression mappings.

## v0.4: asset-identity dataflow

v0.4 adds a source-level dataflow pass in `identity_dataflow.py`. It complements, rather than replaces, the v0.2/v0.3 heuristic scanner.

- Tracks simple Rust assignments and provenance labels for actual token-account Mints, config/reserve/market Mints, config objects, oracle accounts/prices, decimals, and amount inputs.
- Propagates provenance through same-file helper calls using conservative argument-to-parameter mapping and common helper return expressions, bounded by `--max-depth`.
- Looks for explicit actual-Mint-to-config-Mint comparisons and oracle-account-to-config-oracle comparisons in reachable functions and Anchor account contexts.
- Identifies valuation, health, borrow-capacity, liquidation, and withdraw/redeem sinks and reports which provenance categories reach them.
- Maps state-struct fields written in one function and read in other functions, highlighting cross-instruction candidates for Mint, oracle, decimals, LTV, collateral and accounting fields.
- Writes separate `identity_dataflow.json`, `identity_dataflow.csv`, and `identity_dataflow_review/` reports. The original `findings.json`, `findings.csv`, and `review/` formats remain available.
- Includes `test_templates/identity_dataflow_validation_plan.md` to guide protocol-specific manual review and local-only harness validation.

The dataflow pass runs by default. Use `--no-dataflow` to disable it; `--max-depth` controls both the existing call-graph aggregation and v0.4 helper propagation.

### Dataflow status meanings

| Status | Meaning |
|---|---|
| `potential_unbound_mint_to_config_value_flow_review_required` | Actual Mint and config Mint provenance plus config-derived sink flow were observed, but no matching equality guard was found in the analyzed scope. This is a high-priority review lead, **not proof of a vulnerability**. |
| `binding_guard_and_config_value_flow_observed_manual_validation_required` | A comparison pattern and config-derived sink flow were observed. The guard's runtime semantics and execution order still require manual validation. |
| `actual_mint_seen_config_identity_unresolved` | An actual Mint was identified and config-derived sink flow exists, but a config Mint identity could not be resolved. |
| `config_to_value_flow_observed_actual_mint_source_unresolved` | Config-derived data reaches a recognized sink, but actual token-account Mint provenance was not identified. |
| `identity_sources_seen_no_config_value_sink_flow` | Actual and config Mint provenance were seen, but no recognized config-to-sink flow was found in this scope. |
| `insufficient_identity_dataflow_evidence` | The source did not expose enough recognizable structure to make a useful identity-flow statement. This is not a clean bill of health. |

### Synthetic regression examples

```bash
python3 scanner.py --root sample --out reports-v04 --no-review-files
```

- `sample/identity_flow_guarded.rs` models a guarded path, including a Mint check inside a helper.
- `sample/identity_flow_unbound.rs` models an unguarded path that should be elevated for review.
- Both are synthetic fixtures, not source code from yDelta, Kamino, Loopscale, or another live protocol.

### Cross-instruction state-field map

The state-field map links a struct field when a function writes it and a different function reads it. For example, a market's `collateral_mint`, `primary_oracle`, or `collateral_mint_decimals` may be initialized during market creation and consumed during deposit/borrow. This is a field-name relationship only: it does not prove that both functions receive the same runtime PDA/account instance or that the value remains unchanged.

## v0.2 changes

- **Cross-function call-graph aggregation:** follows locally resolvable Rust helper calls up to a configurable depth and aggregates financial, token-transfer, oracle, decimal, and borrow-limit signals.
- **Anchor account-context inspection:** links `Context<InstructionAccounts>` handlers to their `#[derive(Accounts)]` struct so `has_one`, `constraint`, `token::mint`, and related checks are not missed merely because they live outside the handler body.
- **IDL auto-fetch:** `--fetch-idls` asks the Solana IDL Explorer for the current IDL. The service resolves canonical Program Metadata (PMP), fallback PMP, then legacy Anchor IDL. It can return Anchor or Codama IDL shapes.
- **Legacy fallback:** if the IDL Explorer request fails, the scanner tries the legacy Anchor IDL account over the selected Solana RPC.
- **Deployment metadata:** `--fetch-program-metadata` records loader ownership, executable status, ProgramData address, deployment slot, upgrade authority, and a SHA-256 of the raw ProgramData payload.
- **Per-finding review packs:** writes Markdown files with evidence, snippets, manual checks, and local-only invariant test cases.
- **Tests:** unit tests cover helper-call aggregation, Anchor account contexts, nested Anchor IDL accounts, Codama IDL layout, base58, and the synthetic fixture.


## v0.3 automatic discovery

`discover.py` is an additive discovery layer. It does not replace `scanner.py` and the existing v0.2 CLI remains available.

### Discover Solana lending candidates (read-only)

```bash
python3 discover.py --cluster mainnet-beta --out discovery --dry-run
```

The default sources are DeFiLlama's public protocol directory and GitHub repository search. GitHub search is heuristic: a repository result is a research lead, not proof that it is an official protocol repository. Set `GITHUB_TOKEN` to improve GitHub API rate limits. The default RPC is the public Solana mainnet endpoint; for batch use, set `SOLANA_RPC_URL` to a reliable endpoint.

### Export v0.2-compatible targets

```bash
python3 discover.py --cluster mainnet-beta --out discovery \
  --export-targets targets.discovered.json
```

To include addresses that have not passed the RPC executable check, explicitly add `--include-unvalidated-targets`; these are not confirmed program IDs.

### Optional static scan handoff

```bash
python3 discover.py --cluster mainnet-beta --out discovery \
  --export-targets targets.discovered.json --scan \
  --scan-root repos --scan-out reports-discovered
```

The optional handoff invokes the existing scanner only; it does not send transactions. By default, export includes only addresses for which RPC returned `executable=true`. Use `--include-unvalidated-targets` only when you explicitly want an unverified research queue; inspect it manually before scanning. `--scan` requires `--export-targets` and clones only the repositories declared in that exported target file.

### Discovery outputs

- `discovery/discovery.json`: normalized candidates, evidence, score reasons, confidence, RPC results and source failures.
- `discovery/discovery.csv`: compact sortable candidate list.
- `targets.discovered.json`: optional v0.2-compatible target file.
- `.discovery-cache/`: HTTP response cache (six-hour default TTL).

### Important discovery limits

- DeFiLlama identifies protocols, not necessarily Solana program addresses. Program IDs are only populated when a valid public key is found in a GitHub repository description/README; its semantic role still needs manual confirmation.
- GitHub repository search is not authoritative and can return forks, examples, abandoned code or unrelated projects. A GitHub default-branch commit SHA is recorded when available, but it is not proof of the deployed commit.
- A valid 32-byte base58 public key is not necessarily a program. RPC `executable=true` is required before the scanner labels a candidate high confidence; loader owner and deployment metadata still require further review.
- An account that exists but is not executable is retained as evidence but must not be treated as a program.
- Public APIs and public RPC endpoints can rate-limit or fail. Failures are recorded in `source_failures`; cached data may be stale until its TTL expires.
- Scoring prioritizes research, not exploitability or vulnerability severity. Manually review all candidates before scanning.

## Requirements

- macOS or Linux
- Python 3.10+
- Git (only needed for `--clone`)
- Internet access for IDL fetching and RPC metadata. A private RPC endpoint is recommended for batch work.

No Python packages are required.

## Quick start: local fixture

```bash
cd solana-collateral-scanner
python3 -m unittest discover -s tests -v
python3 discover.py --cluster mainnet-beta --out discovery --dry-run
python3 scanner.py --root sample --out reports-demo
```

The sample is synthetic and deliberately vulnerable-looking. It is not source code from a real protocol.

## Batch run against the target list

Clone the public repositories, fetch current IDLs, collect deployment metadata, and scan:

```bash
export SOLANA_RPC_URL="https://YOUR_SOLANA_RPC_ENDPOINT"
python3 scanner.py \
  --clone \
  --fetch-idls \
  --fetch-program-metadata \
  --targets targets.json \
  --root repos \
  --idl-dir idls \
  --out reports
```

For devnet IDL lookup and RPC metadata, set both cluster and RPC URL:

```bash
python3 scanner.py \
  --cluster devnet \
  --rpc-url https://api.devnet.solana.com \
  --fetch-idls --fetch-program-metadata \
  --targets targets.json --root repos --idl-dir idls --out reports-devnet
```

`targets.json` is a research queue. Its `priority` values are scan-order hints, not vulnerability severity ratings or claims that a target is vulnerable. Verify each repository role and source commit before attributing any result to a deployed program.

If you already have source repositories checked out:

```bash
python3 scanner.py --fetch-idls --fetch-program-metadata \
  --targets targets.json --root repos --idl-dir idls --out reports
```

If you only want a static source scan and do not want any network calls:

```bash
python3 scanner.py --root repos --out reports
```

## Outputs

- `reports/findings.json` - full findings and evidence metadata.
- `reports/findings.csv` - spreadsheet-friendly summary.
- `reports/review/*.md` - one review pack per candidate.
- `reports/program_metadata.json` - on-chain loader and deployment metadata when requested.
- `reports/identity_dataflow.json` / `.csv` - v0.5 variable-provenance, selector-flow, and sink-flow triage.
- `reports/identity_dataflow_review/*.md` - per-entrypoint v0.5 evidence and manual validation checklist.
- `idls/*.idl.json` - current IDLs fetched from the IDL Explorer or legacy Anchor fallback.

The ProgramData payload hash is a chain-state fingerprint, **not** a source-to-binary verification result. Loader-allocated trailing padding may be included. Use a verifiable-build workflow and exact source commit to establish source/binary equivalence.

## What the scanner checks

1. Financial entrypoints: deposit, collateral, borrow, repay, withdraw, liquidation, redeem, LTV, health, reserve.
2. Asset selectors: asset ID/index, collateral ID, reserve index, config, market, and related selectors.
3. Token movement: SPL Token / Token-2022 transfer and transfer-checked paths.
4. Valuation: Pyth, Switchboard, oracle, feed, and price handling.
5. Unit conversion: Mint decimals, config decimals, scaling, powers of ten, and UI amount conversion.
6. Dynamic accounts: `remaining_accounts`, `AccountInfo`, and `UncheckedAccount`.
7. Borrow/value sinks: borrow capacity, LTV, collateral value, and health calculations.
8. Identity checks: mint-to-config and oracle-to-config checks in handler/helper bodies and Anchor `Accounts` structs.

## Important analysis limits

- The v0.2/v0.3 cross-function pass is **call-graph signal aggregation**, not compiler-grade variable-level def-use analysis.
- The v0.4/v0.5 dataflow pass adds heuristic assignment/provenance tracking, helper argument/parameter propagation, common return propagation, and state-field reference mapping. It is still not compiler-grade: Rust traits, macros, dynamic dispatch, complex generics, generated code, CPI semantics, account deserialization, PDA derivations, aliasing, and cross-crate flows may be missed or over-approximated.
- A reported Mint comparison pattern does not prove that the check is enforced before state changes or on every execution path. A missing pattern is not proof that the program is exploitable.
- Cross-instruction state-field links are based on struct and field names; they do not prove same-account identity, PDA equality, or value preservation.
- Calls are resolved conservatively by function name, preferring same-file definitions and skipping ambiguous cross-file names. Rust traits, macros, dynamic dispatch, generated code, and complex module paths can still be missed.
- Anchor account-context parsing is best-effort. Non-Anchor Rust programs and custom account validation require manual review.
- IDL account names and arguments do not prove runtime constraints. An IDL can be stale or intentionally incomplete.
- The IDL Explorer service is an external lookup dependency. If it is unavailable, legacy Anchor fallback only works for programs that still publish the legacy IDL account.
- The scanner does not decompile SBF binaries, reconstruct historical source, or verify source-to-binary equivalence.
- Program metadata and source repositories may be read at different slots/commits. Record the exact deployment slot and source commit before making a mainnet conclusion.
- The scanner does not automatically execute LiteSVM/Mollusk tests. It generates local-only invariant test plans; each protocol needs a protocol-specific harness with the real account layout and instruction builder.

## Manual verification checklist

For each candidate, trace one instruction end to end:

- Which SPL Mint owns the user's source token account?
- Which Mint owns the vault destination token account?
- Which argument or PDA selects the collateral/reserve configuration?
- Does that exact config contain the same Mint, and is equality enforced on-chain?
- Which oracle account/feed is read, and is its owner/feed identity validated against that config?
- Which decimals are used, and are they derived from the validated Mint or a trusted immutable config?
- Does the resulting value flow into collateral shares, health, LTV, or borrow capacity?
- If validation fails, are all relevant state updates rolled back atomically?
- Does the source commit match the deployed program build?

## Local-only test plan

See `test_templates/identity_invariant_plan.md`. The negative cases use synthetic Mints with different decimals and mismatched config/oracle accounts. Adapt the plan to LiteSVM or Mollusk using the exact protocol instruction/account layout. Do not submit test transactions to production markets or use third-party funds without explicit authorization.


## v0.3.1 updates (carried into v0.4)

- Static findings now include `identity_assessment` and `assessment_limit`. These describe visible source patterns only; they do not prove runtime safety or exploitability.
- GitHub-discovered repositories now receive a conservative `repo_role` hint. `research_poc` and `audit` repositories must not be treated as protocol source. No GitHub search result is automatically certified as official deployed source.
- `targets.json` now includes yDelta as a curated target. Its fixed-rate path is recorded as a **partial negative regression reference** based on supplied manual review notes. It is not a whole-program safety verdict.
- See `audit/ydelta-fixed-rate-review.md` and `test_templates/ydelta_fixed_rate_regression_plan.md`. The seven cases are a test plan, not a runnable yDelta harness.

Run tests:

```bash
python3 -m unittest discover -s tests -v
```



## v0.4.0 historical baseline

- Added `identity_dataflow.py` for assignment-level asset-identity provenance analysis.
- Added conservative helper-call argument/parameter propagation and common return-expression summaries.
- Added actual Mint/config Mint and oracle/config-oracle guard detection.
- Added valuation/health/borrow/liquidation/withdraw sink provenance summaries.
- Added cross-instruction state-struct field writer/reader mapping.
- Added separate JSON, CSV and Markdown dataflow review outputs without replacing the existing scanner report schema.
- Added guarded/unbound synthetic fixtures and dataflow regression tests.
- Preserved the v0.2/v0.3 scanner CLI and discovery workflow; `--no-dataflow` disables the new pass.
- yDelta remains a user-supplied partial negative review reference. The v0.4 yDelta-style regression test is synthetic and does not independently scan or validate yDelta source or deployed code.


## v0.5.0 release notes

- Cumulatively includes the planned v0.4.1 detection-calibration work; no separate v0.4.1 release is required.
- Added `protocol_analysis.py` with structured Anchor `Accounts`/field-attribute extraction, including Mint and oracle identity chains.
- Added Token-2022 extension policy signals and explicit review statuses rather than treating extension mentions as vulnerabilities.
- Added financial arithmetic review for unchecked subtraction and checked/saturating/wrapping operations.
- Added `*_checks` helper functions as eligible dataflow roots.
- Added numeric/untyped asset-selector provenance and selector-to-config/value-sink review status.
- Added a dedicated `flash_repay` account-flow review marker.
- Added four synthetic protocol-inspired regression fixtures for Loopscale selector, Kamino extension/arithmetic/flash-repay, Marginfi Anchor binding, and yDelta Anchor binding. These fixtures are not production protocol source.
- Added `protocol_analysis.json`, `.csv`, and Markdown review packs; preserved all v0.2/v0.3/v0.4 CLI and report outputs.
- Added `--no-protocol-analysis`; `--no-dataflow` remains independent.
- All findings remain static review leads. No live protocol was scanned or dynamically validated as part of this release.


## License

This project is licensed under the [MIT License](LICENSE). The license applies to the project materials authored for this repository. Third-party components and referenced projects remain subject to their own licenses and terms.
