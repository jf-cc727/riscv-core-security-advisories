# CVA6 VS-mode Invalid SFENCE.VMA Trap-Bypass Package

This package is for CVE review.

Issue link: `https://github.com/openhwfoundation/cva6/issues/3459`

Validated: CVA6 `v5.3.0-168-gcd4c8b17`, confirmed at commit `cd4c8b17c102`, `cv64a6_imafdch_sv39` Hypervisor configuration.

Merged fix: PR `https://github.com/openhwfoundation/cva6/pull/3470`, merged as commit `288a27cf46b8d5d19f2efbff35aa88c18446666f`.

Candidate title: CVA6 VS-mode invalid SFENCE.VMA trap bypass

Security PoC: the invalid VS-mode `SFENCE.VMA` encoding with `rd != x0` bypasses the illegal-instruction trap and performs a real VS TLB flush side effect, refreshing a stale translation to a newly mapped secret page.

## What is in this package
- `VULNERABILITY_REPORT.md` and `VULNERABILITY_REPORT.pdf`: the main report.
- `poc/poc.S`, `poc/poc.elf`, and `poc/poc.cva6-h.log`: the security PoC and evidence.

## How to read it
Read `VULNERABILITY_REPORT.md` first. The public issue tracks the
architectural bug; this package preserves the security PoC and CVE-oriented
impact analysis.
