# CVA6 Sv39 Malformed Non-Leaf PTE Guard Bypass Package

This package is for CVE review.

Issue link: `https://github.com/openhwfoundation/cva6/issues/3420`

Validated: CVA6 `v5.3.0-168-gcd4c8b17`, confirmed at commit `cd4c8b17c102`, non-H `cv64a6_imafdc_sv39` configuration.

Merged fix: PR `https://github.com/openhwfoundation/cva6/pull/3422`, merged as commit `f7c04c3721693b1c9045ae8a8da0ed6ac1f68cf8`.

Candidate title: CVA6 Sv39 malformed non-leaf PTE guard bypass

Security PoC: an S-mode workload reaches a retained readable leaf behind an architecturally faulting malformed root entry and copies a protected word into an attacker-visible buffer.

## What is in this package
- `VULNERABILITY_REPORT.md` and `VULNERABILITY_REPORT.pdf`: the main report.
- `poc/poc.S`, `poc/poc.elf`, and `poc/poc.cva6.log`: the security PoC and evidence.

## How to read it
Read `VULNERABILITY_REPORT.md` first. The public issue tracks the
architectural bug; this package preserves the security PoC and CVE-oriented
impact analysis.
