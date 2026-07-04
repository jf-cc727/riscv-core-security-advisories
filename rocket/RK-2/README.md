# Rocket Chip H-Extension hedeleg Delegation Package

This package is for CVE-oriented review of RK-2.

## Version Context

This package was validated against the official Rocket Chip `master` line at
revision `v1.6-819-g55bcad0f5`, confirmed at commit
`55bcad0f59436de98ea510334121de8546b9e9d7`, using
`freechips.rocketchip.system.HypervisorConfig`. No fix revision has been
identified yet.

## Candidate Title

Rocket Chip masks required-writable `hedeleg[18:19]` bits in H-enabled configurations

## Reading Order

1. Read `VULNERABILITY_REPORT.md`.
2. Inspect `poc/poc.S` for the HS-mode `hedeleg` proof of concept.
3. Check `poc/official-rocket-hypervisor-seed1-evidence.txt` for compact official-run evidence.

## Contents

- `VULNERABILITY_REPORT.md`: main CVE-oriented report.
- `poc/poc.S`: minimal proof of concept.
- `poc/poc.objdump.txt`: disassembly of the rebuilt PoC artifact used for evidence.
- `poc/official-rocket-hypervisor-seed1-evidence.txt`: compact evidence from the official latest Rocket H-enabled run.
- `poc/poc.official-rocket-hypervisor.seed1.log`: fixed-seed official emulator result.
- `poc/poc.official-rocket-hypervisor.seed1.rc`: fixed-seed official emulator return code (`61`).
