# Rocket Chip Security Advisories

Public advisory packages for Rocket Chip related findings.

## Published Packages

- [RK-1: PMP CSR reserved encoding after reset](RK-1/)
  - Affected revision: `v1.6-819-g55bcad0f5`
    (`55bcad0f59436de98ea510334121de8546b9e9d7`)
  - Configuration: `freechips.rocketchip.system.DefaultConfig`

- [RK-2: H-extension hedeleg[18:19] write/readback masking](RK-2/)
  - Affected revision: `v1.6-819-g55bcad0f5`
    (`55bcad0f59436de98ea510334121de8546b9e9d7`)
  - Configuration: `freechips.rocketchip.system.HypervisorConfig`

- [RK-3: VS sstatus host-state disclosure](RK-3/)
  - Affected revision: `v1.6-819-g55bcad0f5`
    (`55bcad0f59436de98ea510334121de8546b9e9d7`)
  - Configuration: `freechips.rocketchip.system.HypervisorConfig`

The public packages intentionally include source and evidence artifacts rather
than prebuilt ELF binaries.
