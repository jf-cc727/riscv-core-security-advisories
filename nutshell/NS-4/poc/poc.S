/*
 * Back-to-back minstret visibility lag can keep a one-shot window open
 *
 * M-mode models a monitor that keeps a one-shot less-privileged service window
 * open until a live retired-instruction count rises above a fixed threshold.
 * The monitor performs one audit read into x0 and then uses the next visible
 * read as the authoritative live sample.
 *
 * Correct behavior:
 *   the authoritative visible read includes the retirement of the audit read
 *   the extra service is denied
 *
 * Vulnerable behavior:
 *   the authoritative visible read lags by one
 *   the monitor undercounts the live window and grants one extra
 *   less-privileged service
 */
.option push
.option norelax
.option norvc

.equ MSTATUS_MPP_MASK, 0x00001800
.equ MSTATUS_MPP_S,    0x00000800
.equ CAUSE_ECALL_S,    9

.macro EXIT code
  li   a0, \code
  la   t5, tohost
  li   t6, (((\code) * 2) + 1)
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
1:
  j 1b
.endm

.section .text.init, "ax"
.globl _start
_start:
  la   t0, m_trap
  csrw mtvec, t0
  csrw medeleg, zero
  csrw mideleg, zero

  csrr zero, minstret
  csrr s0, minstret

  /*
   * The service window should already be closed once the live sample rises
   * above 5. A one-instruction undercount keeps it open on NutShell.
   */
  li   t1, 5
  bleu s0, t1, grant_extra_service
  j    deny_extra_service

grant_extra_service:
  li   t0, MSTATUS_MPP_MASK
  csrc mstatus, t0
  li   t0, MSTATUS_MPP_S
  csrs mstatus, t0
  la   t0, s_extra_service
  csrw mepc, t0
  mret

  EXIT 44

.align 2
s_extra_service:
  ecall
  EXIT 45

.align 2
m_trap:
  csrr t0, mcause
  li   t1, CAUSE_ECALL_S
  bne  t0, t1, fail_wrong_cause
  EXIT 31

deny_extra_service:
  EXIT 0

fail_wrong_cause:
  EXIT 32

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0
.globl fromhost
fromhost:
  .dword 0

.option pop
