# Release Checklist

Before publishing a release:

- [x] Select and add the MIT License (`LICENSE`).
- [ ] Confirm the repository visibility and maintainer identity.
- [ ] Re-run `python3 -m unittest discover -s tests -v`.
- [ ] Run `python3 scanner.py --root sample --out reports-release-check`.
- [ ] Confirm generated runtime directories and local secrets are excluded by `.gitignore`.
- [ ] Review `targets.json` and research notes for authorization, disclosure, and publication scope.
- [ ] Confirm all protocol-inspired fixtures are labeled synthetic.
- [ ] Confirm no static finding is described as a confirmed vulnerability without independent evidence.
- [ ] Record the exact source commit, test environment, and release date.
- [ ] Create the release tag only after the public repository is verified.
