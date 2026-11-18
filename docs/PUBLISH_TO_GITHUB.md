# Publish this prepared project to GitHub

The repository contents are prepared for the GitHub account `madfloyd2016`. The GitHub repository itself has not yet been created.

## 1. Create the empty repository

1. Open <https://github.com/new> while signed in as `madfloyd2016`.
2. Set the repository name to `solana-collateral-scanner`.
3. Choose **Public** if you intend to use it as public research evidence.
4. Do not initialize it with a README, `.gitignore`, or license; those files are already included here.
5. Create the repository.

## 2. Push this directory

Extract the release ZIP, open a terminal in the `solana-collateral-scanner` directory, and run:

```bash
git init -b main
git add .
git commit -m "Initial public release: Solana Collateral Identity Scanner v0.5.0"
git remote add origin https://github.com/madfloyd2016/solana-collateral-scanner.git
git push -u origin main
```

## 3. Create the v0.5.0 tag

Only after checking the pushed repository contents, create and push the release tag:

```bash
git tag -a v0.5.0 -m "Solana Collateral Identity Scanner v0.5.0"
git push origin v0.5.0
```

## 4. Publish the GitHub Release

Create a GitHub Release for tag `v0.5.0`. Use `docs/GITHUB_RELEASE_v0.5.0.md` as the release description. Attach the release ZIP if you want to preserve the exact prepared source bundle as a downloadable artifact.

## Before making the repository public

- Confirm the maintainer identity and `Copyright (c) 2026 madfloyd2016` are correct.
- Review every file for secrets, private RPC URLs, private keys, non-public target data, and third-party code that you do not have permission to publish.
- Confirm the research notes and `targets.json` are suitable for public disclosure.
- Keep the synthetic-fixture and static-analysis limitations visible.
- Do not describe the sample findings as confirmed vulnerabilities.

This preparation does not create the GitHub repository or publish a release. Those actions require the account holder to create the repository and push the contents.
