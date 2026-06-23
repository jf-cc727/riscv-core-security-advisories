/*
 * Stale minstret reset can poison a monitor's fresh-baseline decision
 *
 * M-mode models a monitor that clears minstret before entering a less-privileged
 * victim compartment. If the immediately following read is still nonzero, the
 * monitor concludes the victim already exhausted its fresh budget and denies
 * entry.
 *
 * Correct behavior:
 *   csrw minstret, zero ; csrr minstret  -> 0
 *   victim compartment is entered
 *
 * Vulnerable behavior:
 *   csrr observes stale pre-clear state
 *   monitor denies the victim compartment immediately
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

  /* Fresh accounting baseline for the next compartment. */
  csrw minstret, zero
  csrr s0, minstret

  bnez s0, deny_victim_compartment

  li   t0, MSTATUS_MPP_MASK
  csrc mstatus, t0
  li   t0, MSTATUS_MPP_S
  csrs mstatus, t0
  la   t0, s_victim_service
  csrw mepc, t0
  mret

  EXIT 41

.align 2
s_victim_service:
  ecall
  EXIT 42

.align 2
m_trap:
  csrr t0, mcause
  li   t1, CAUSE_ECALL_S
  bne  t0, t1, fail_wrong_cause
  EXIT 0

deny_victim_compartment:
  EXIT 31

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
