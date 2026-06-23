# NutShell Translated Store Access-Fault Suppression Package

This package is for CVE review.

Issue link: `https://github.com/OSCPU/NutShell/issues/262`

This package is based on the official `release-211228` release tag and was confirmed affected at revision `release-211228-142-g041f694` (`041f694965728ea183a0622daa1734002bf4621e`). No local fix revision has been identified yet.

**Candidate title.** OSCPU NutShell may retire translated stores without the required Store/AMO access fault, weakening physical protection boundaries

The public issue only states the architectural bug. The security setting, the separate security PoC, and the extra evidence stay in this package.

## What is in this package
- `VULNERABILITY_REPORT.md` and `VULNERABILITY_REPORT.pdf`: the main report.
- `poc/issue-context.replay.log` and `poc/image/issue-context-actual.png`: the issue-level architectural replay excerpt.
- `poc/poc.S`, `poc/poc.elf`, `poc/poc.nutshell.replay.log`, `poc/poc.nutshell.nodiff.log`, and the matching screenshots: the security PoC and its evidence.

## How to read it
Read `VULNERABILITY_REPORT.md` first. The report is split into two tracks: the issue-level architectural reproduction, and the separate security PoC with impact evidence.
