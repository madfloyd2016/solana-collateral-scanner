# Security Policy

## Scope

This policy covers vulnerabilities in Solana Collateral Scanner itself, including its source parsers, report generation, discovery pipeline, and handling of local configuration.

The scanner is a read-only research tool. It does not sign or submit transactions, move funds, or exploit live programs.

## Reporting a vulnerability

Please do not publish exploitable details, credentials, private RPC URLs, or unpatched vulnerability information in a public issue.

If GitHub private vulnerability reporting is enabled for this repository, use that channel. Otherwise, contact the maintainer through the contact method on the GitHub profile and include:

- A concise description and affected version or commit.
- Reproduction steps using a local or synthetic fixture.
- Expected and observed behavior.
- Any suggested mitigation.

Do not include private keys, seed phrases, access tokens, or third-party user data.

## Research boundaries

Use the scanner only against source code and infrastructure that you own or are expressly authorized to assess. Respect each program's bug bounty, coordinated disclosure, and testing rules. Do not submit transactions or test against production user funds as part of scanner validation.

## Response expectations

The maintainer will make a best-effort attempt to acknowledge reports, reproduce issues, and coordinate a fix. No response-time SLA is provided.
