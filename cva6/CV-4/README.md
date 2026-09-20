# CVA6 mtvec Readback / Trap-Dispatch Low-Alias Entry Package

This package is for CVE review.

Issue link: `https://github.com/openhwfoundation/cva6/issues/3458`

Validated: CVA6 `v5.3.0-168-gcd4c8b17`, confirmed at commit `cd4c8b17c102`, non-H `cv64a6_imafdc_sv39` configuration.

Proposed fix PR: `https://github.com/openhwfoundation/cva6/pull/3566`. At the
time this package was prepared, GitHub reported this PR as open and not merged.

Candidate title: CVA6 mtvec readback / trap-dispatch low-alias entry

Security PoC: S-mode prepares a low-address payload buffer, M-mode validates a high-tagged `mtvec` value by readback, and a later M-mode trap enters the S-prepared low alias.

## What is in this package
- `VULNERABILITY_REPORT.md` and `VULNERABILITY_REPORT.pdf`: the main report.
- `poc/poc.S`, `poc/poc.elf`, and `poc/poc.cva6.log`: the security PoC and evidence.

## How to read it
Read `VULNERABILITY_REPORT.md` first. The public issue tracks the
architectural bug; this package preserves the security PoC and CVE-oriented
impact analysis.
