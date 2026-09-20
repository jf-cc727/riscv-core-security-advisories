# CVA6 RVH HLVX-to-HLV Execute-Only Disclosure Package

This package is for CVE review.

Issue link: `https://github.com/openhwfoundation/cva6/issues/3456`

Validated: CVA6 `v5.3.0-168-gcd4c8b17`, confirmed at commit `cd4c8b17c102`, `cv64a6_imafdch_sv39` Hypervisor configuration.

Merged fix: PR `https://github.com/openhwfoundation/cva6/pull/3468`, merged as commit `2d2d0c11b750e6ad92e828987b24d6398404fc0b`.

Candidate title: CVA6 RVH HLVX-to-HLV execute-only disclosure

Security PoC: an internal `HLVX.WU` access to a G-stage execute-only page lets a later caller-visible `HLV.WU` copy protected contents into an attacker-visible buffer.

## What is in this package
- `VULNERABILITY_REPORT.md` and `VULNERABILITY_REPORT.pdf`: the main report.
- `poc/poc.S`, `poc/poc.elf`, and `poc/poc.cva6-h.log`: the security PoC and evidence.

## How to read it
Read `VULNERABILITY_REPORT.md` first. The public issue tracks the
architectural bug; this package preserves the security PoC and CVE-oriented
impact analysis.
