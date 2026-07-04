# Rocket Chip PMP CSR Reserved Encoding Package

This package is for CVE-oriented review of RK-1.

## Version Context

This package was validated against the official Rocket Chip `master` line at
revision `v1.6-819-g55bcad0f5`, confirmed at commit
`55bcad0f59436de98ea510334121de8546b9e9d7`, using
`freechips.rocketchip.system.DefaultConfig`. No fix revision has been
identified yet.

## Candidate Title

Rocket Chip exposes invalid PMP permission state in `pmpcfg0` after reset

## Reading Order

1. Read `VULNERABILITY_REPORT.md`.
2. Inspect `poc/poc.S` for the minimal PMP CSR reset/readback proof of concept.
3. Check `poc/official-rocket-master-seed1-evidence.txt` for the compact official-run evidence.

## Contents

- `VULNERABILITY_REPORT.md`: main CVE-oriented report.
- `poc/poc.S`: minimal proof of concept.
- `poc/poc.objdump.txt`: disassembly of the rebuilt PoC artifact used for evidence.
- `poc/official-rocket-master-seed1-evidence.txt`: compact evidence excerpt from the official latest Rocket run, including the verbose CSR readback line.
- `poc/poc.official-rocket-master.seed1.log`: fixed-seed official emulator result.
- `poc/poc.official-rocket-master.seed1.rc`: fixed-seed official emulator return code (`93`).
- `poc/images/figure33-pmpcfg.svg`: RISC-V Figure 33 PMP configuration format used by the Markdown report.
- `poc/images/figure33-pmpcfg.png`: rendered copy of Figure 33.
