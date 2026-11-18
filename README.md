# Solana Collateral Identity Scanner

**Version:** 0.5.0  
**Maintainer:** [@madfloyd2016](https://github.com/madfloyd2016)  
**License:** MIT

A read-only research tool for triaging asset-identity, collateral valuation, Token-2022 authority, vault-accounting, arithmetic, and flash-repay code paths in Solana DeFi programs.

## Scope and safety

This tool performs source-level static analysis and read-only metadata discovery. It does not sign or submit transactions, move funds, or exploit live programs. Findings are review leads, not confirmed vulnerabilities. Use it only on code and systems you own or are expressly authorized to assess.

## Features

- Heuristic Rust source scanning for financial instructions, token movement, oracle/price handling, decimals, selectors, and config references.
- Asset-identity dataflow review across actual token-account Mint, config/reserve/market Mint, oracle, decimals, and valuation/borrow sinks.
- Best-effort Anchor `#[derive(Accounts)]` and `#[account(...)]` constraint mapping.
- Token-2022 extension policy signals and arithmetic review leads.
- Flash-repay account-flow coverage markers.
- JSON, CSV, and Markdown review outputs.
- Synthetic regression fixtures for selector, extension/arithmetic, and Anchor-binding patterns.

## Quick start

Requires Python 3.10+.

```bash
python3 -m unittest discover -s tests -v
python3 scanner.py --root sample --out reports-v05
```

## CLI

```bash
# Full scan: legacy scanner + identity dataflow + protocol analysis
python3 scanner.py --root repos --out reports

# Disable identity dataflow
python3 scanner.py --root repos --out reports --no-dataflow

# Disable protocol-aware analysis
python3 scanner.py --root repos --out reports --no-protocol-analysis
```

## Important limitations

This is a heuristic source analyzer, not a Rust compiler-grade MIR/SSA analyzer. Anchor attributes are syntactic evidence, not proof of runtime identity or execution order. Static signals, arithmetic leads, Token-2022 extension mentions, and flash-repay coverage markers do not establish exploitability. Synthetic fixtures are not production protocol source. GitHub repository identity and an on-chain Program ID do not prove source-to-binary equivalence.

The project does not claim that any production protocol has been re-scanned or that any mainnet vulnerability has been confirmed. Review `audit/`, `docs/RESEARCH_SCOPE.md`, and `SECURITY.md` for research provenance, scope, and disclosure guidance.

## License

MIT. See [LICENSE](LICENSE).
