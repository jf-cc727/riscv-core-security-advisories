# CVA6 Security Advisories

Published advisory packages in this directory:

- [CV-1](./CV-1/README.md): RVH `HLVX` to `HLV` execute-only disclosure
- [CV-2](./CV-2/README.md): Sv39 malformed non-leaf PTE guard bypass
- [CV-3](./CV-3/README.md): `medeleg[9]` missing trap-surface bypass
- [CV-4](./CV-4/README.md): `mtvec` readback / trap-dispatch low alias
- [CV-5](./CV-5/README.md): VS-mode invalid `SFENCE.VMA` trap bypass
- [CV-6](./CV-6/README.md): VS FP-state lazy-save disclosure

Downloadable package archives are available in [`packages/`](./packages/).

These reports were originally validated on CVA6 `v5.3.0-168-gcd4c8b17`,
confirmed at commit `cd4c8b17c102`. Public CVA6 issue and fix references are
listed in each package README.
