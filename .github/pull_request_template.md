## Summary

<!-- Describe user-visible behavior and why the change is needed. -->

## Change impact

<!-- Use docs/change-impact.md. Identify architecture, security, data, channel,
extension/Canvas, release/installer, CI/governance, and dependency effects. -->

## Security impact

## Verification

- [ ] `npm run verify`
- [ ] `git diff --check`
- [ ] Runtime/security changes include focused deterministic regression tests
- [ ] No real iLink login, external network, credentials, or messages in default tests
- [ ] No secrets, credentials, daemon data, or private paths added
- [ ] No generated archives, installers, checksums, coverage, or build output added
- [ ] Release/installer reproducibility remains covered when packaging changes
- [ ] Extension reloaded/inspected when extension code changed
- [ ] Protected changes have a fresh `manual-governance` label from a non-author maintainer

## Tracking issue

Fixes #
