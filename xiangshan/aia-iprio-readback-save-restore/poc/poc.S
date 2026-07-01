/*
 * XS-CVE-04:
 *   AIA iprio readback is dynamically masked by mie and can corrupt
 *   firmware interrupt-priority save/restore state.
 *
 * Safe scenario:
 *   M-mode firmware configures PrioSSI, enters a critical section by clearing
 *   mie.SSIE, saves iprio0 through miselect/mireg, then restores the saved
 *   value. Correct hardware preserves the configured priority while delivery
 *   is disabled. A vulnerable DUT reads zero while mie.SSIE is clear, then the
 *   restore path writes that zero back and permanently downgrades PrioSSI.
 *
 * Exit codes:
 *   0   expected: priority survives disable + save/restore
 *   31  suspected bug: save/restore persistently cleared PrioSSI
 *   40  field/window unsupported or read-only zero
 *   41  unexpected priority value after restore
 *   60  unexpected trap
 */

.option push
.option norelax
.option norvc

.equ MIE_SSIE,      0x2
.equ IPRIO0_SELECT, 0x30
.equ PRIO_MASK,     0x000000000000ff00
.equ PRIO_VALUE,    0x0000000000000100

.macro EXIT code
  li   a0, \code
  la   t4, tohost
  slli t5, a0, 1
  ori  t5, t5, 1
  sd   t5, 0(t4)
  fence
  .word 0x0005006b
1:
  j 1b
.endm

.section .text.init, "ax"
.globl _start
_start:
  la   t0, unexpected_trap
  csrw mtvec, t0

  /*
   * Establish that mie.SSIE is implemented/writable, so the matching iprio
   * byte should not be read-only zero solely because the current enable is 0.
   */
  li   t0, MIE_SSIE
  csrs mie, t0
  csrr t1, mie
  and  t1, t1, t0
  beqz t1, inconclusive

  /* Select machine iprio0 and prove PrioSSI can hold a non-zero value. */
  li   t1, IPRIO0_SELECT
  csrw 0x350, t1

  li   t2, PRIO_VALUE
  csrw 0x351, t2

  csrr t3, 0x351
  li   t2, PRIO_MASK
  and  t3, t3, t2
  li   t2, PRIO_VALUE
  bne  t3, t2, inconclusive

  /*
   * Firmware critical section: interrupt delivery is disabled, but the iprio
   * configuration value remains architecturally implemented state.
   */
  li   t0, MIE_SSIE
  csrc mie, t0

  /* Firmware saves the selected iprio window while SSIE is disabled. */
  csrr t3, 0x351
  la   t4, saved_iprio0
  sd   t3, 0(t4)

  /* Firmware later restores exactly what it saved. */
  ld   t3, 0(t4)
  csrw 0x351, t3

  /* Re-enable SSIE and inspect whether restore corrupted the priority. */
  csrs mie, t0

  csrr t3, 0x351
  li   t2, PRIO_MASK
  and  t3, t3, t2

  li   t2, PRIO_VALUE
  beq  t3, t2, pass

  beqz t3, bug_persistent_priority_loss
  EXIT 41

pass:
  EXIT 0

bug_persistent_priority_loss:
  EXIT 31

inconclusive:
  EXIT 40

unexpected_trap:
  csrr s0, mcause
  csrr s1, mepc
  EXIT 60

.section .data, "aw"
.align 3
saved_iprio0:
  .dword 0

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0
.globl fromhost
fromhost:
  .dword 0

.option pop
