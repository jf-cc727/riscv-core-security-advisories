# Rocket Chip VS `sstatus` Host-State Disclosure Package

This package is for CVE-oriented review of RK-3.

## Version Context

This package was validated against the official Rocket Chip `master` line at
revision `v1.6-819-g55bcad0f5`, confirmed at commit
`55bcad0f59436de98ea510334121de8546b9e9d7`, using
`freechips.rocketchip.system.HypervisorConfig`. No fix revision has been
identified yet.

Security PoC: a VS guest reads `sstatus`, observes HS host `FS=Dirty, SD=1` instead of guest `vsstatus.FS=Initial, SD=0`, stores the observed word in `attacker_buffer`, and exits with `tohost = 31`.

## Candidate Title

Rocket Chip VS-mode `sstatus` read may expose HS host extended-state status

## Reading Order

1. Read `VULNERABILITY_REPORT.md`.
2. Inspect `poc/poc.S` for the VS-mode `sstatus` read-view proof of concept.
3. Check `poc/official-rocket-hypervisor-seed1-evidence.txt` and `poc/poc.rocket-diff.log` for official-run and replay evidence.

## Contents

- `VULNERABILITY_REPORT.md`: main CVE-oriented report.
- `poc/poc.S`: minimal proof of concept.
- `poc/poc.objdump.txt`: disassembly of the rebuilt PoC artifact used for evidence.
- `poc/official-rocket-hypervisor-seed1-evidence.txt`: compact evidence from the official latest Rocket H-enabled run.
- `poc/poc.official-rocket-hypervisor.seed1.log`: fixed-seed official emulator result.
- `poc/poc.official-rocket-hypervisor.seed1.rc`: fixed-seed official emulator return code (`31`).
- `poc/poc.rocket-diff.log`: replay evidence showing the guest-visible `sstatus` value mismatch.
