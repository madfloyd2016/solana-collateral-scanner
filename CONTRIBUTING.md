# Contributing

Thank you for helping improve Solana Collateral Scanner.

## Development setup

- Python 3.10 or newer
- No third-party Python packages are required by the current test suite

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

Run the scanner against the synthetic fixtures:

```bash
python3 scanner.py --root sample --out reports-demo
```

Run discovery in dry-run mode:

```bash
python3 discover.py --cluster mainnet-beta --out discovery --dry-run
```

## Changes to detection logic

- Add a focused regression test for every new detection rule.
- Prefer both positive and negative fixtures so that a guard or safe pattern is not incorrectly reported as an unbound identity path.
- Keep protocol-inspired fixtures synthetic. Do not copy private, embargoed, or unauthorized production code into the repository.
- Separate static signals, manual-review candidates, local validation, and confirmed findings.
- A coverage marker is not a vulnerability finding.
- Preserve the existing `scanner.py` and `discover.py` CLI behavior unless a change is explicitly documented.
- Document parser assumptions and known false-positive / false-negative cases.

## Pull requests

Please include:

1. The problem being addressed and the relevant research question.
2. A concise explanation of the implementation.
3. Tests added or updated and their results.
4. Any limitations or cases the change does not cover.
5. Confirmation that no secrets, private RPC credentials, private keys, or non-public target data are included.

## Responsible testing

Use local fixtures, local validators, or explicitly authorized environments. Do not submit transactions, borrow, liquidate, transfer assets, or interact with production user funds as part of tests for this project.
