# CVA6 VS FP-State Lazy-Save Disclosure Package

This package is for CVE review.

Issue link: `https://github.com/openhwfoundation/cva6/issues/3460`

Validated: CVA6 `v5.3.0-168-gcd4c8b17`, confirmed at commit `cd4c8b17c102`, `cv64a6_imafdch_sv39` Hypervisor configuration.

Merged fix: PR `https://github.com/openhwfoundation/cva6/pull/3469`, merged as commit `6ee41edb289f9480282493388ae39693df69f76d`.

Candidate title: CVA6 VS FP-state lazy-save disclosure

Security PoC: a VS-mode lazy-save scheduler observes stale `sstatus.SD=0` immediately after context A dirties FP state, skips save/clear, and context B reads A's FP marker from `ft0`.

## What is in this package
- `VULNERABILITY_REPORT.md` and `VULNERABILITY_REPORT.pdf`: the main report.
- `poc/poc.S`, `poc/poc.elf`, and `poc/poc.cva6-h.log`: the security PoC and evidence.

## How to read it
Read `VULNERABILITY_REPORT.md` first. The public issue tracks the
architectural bug; this package preserves the security PoC and CVE-oriented
impact analysis.
