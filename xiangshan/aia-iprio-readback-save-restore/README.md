# XiangShan AIA Save/Restore Supplement

Validated on Kunminghu-v3 `v3.2.2-alpha-1931-g96c3f568f`
(`96c3f568f943a096ffd3d712dc6f462ac4b1ba33`).

Vendor status: the XiangShan security team confirmed reproduction and provided
the following public fix PRs for review:
https://github.com/OpenXiangShan/XiangShan/pull/6128 and
https://github.com/OpenXiangShan/NEMU/pull/1099.

![Vendor confirmation](vendor-confirmation-redacted.png)

## At A Glance

- Security story:
  trusted firmware / monitor code saves host-owned AIA priority state while
  delivery is masked, then restores it later. The vulnerable DUT returns a
  false zero during the save, so the later restore persistently clears the
  configured host interrupt priority.
- Impact:
  integrity failure in host interrupt-priority policy, with possible secondary
  availability effects on ordering or latency.
- Main evidence:
  `poc.xiangshan.nodiff.log` reaches the `bug_persistent_priority_loss` witness;
  `poc.xiangshan.replay.log` documents the current AIA diff-reference limit and
  is supporting context rather than the primary evidence.

## Files

- `VULNERABILITY_REPORT.md`
  - full security narrative, evidence, and figures
- `poc/poc.S`
  - main AIA save/restore corruption PoC
- `poc/poc.objdump.txt`
  - save/restore path and witness exit
- `poc/poc.xiangshan.replay.log`
  - AIA diff-reference limitation context
- `poc/poc.xiangshan.nodiff.log`
  - DUT-only witness of persistent priority loss
- `poc/realistic_aia_save_restore_sketch.c`
  - monitor / firmware lifecycle sketch
- `poc/images/`
  - specification and security-story figures copied from the original bundle
- `vendor-confirmation-redacted.png`
  - cropped vendor confirmation screenshot without email headers
