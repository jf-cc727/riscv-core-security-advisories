/*
 * H-extension hedeleg[18:19] writability probe.
 *
 * EXIT 0  : bits are writable/readable
 * EXIT 61 : bits are masked to zero
 * EXIT 62 : H extension/CSR absent or illegal
 */
.option push
.option norelax
.option norvc

.equ CSR_HEDELEG, 0x602
.equ HEDELEG_18_19, 0x000c0000
.equ MSTATUS_MPP_MASK, 0x00001800
.equ MSTATUS_MPP_S,    0x00000800

.macro EXIT code
  li   a0, \code
  la   t5, tohost
  li   t6, (((\code) << 1) | 1)
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
.endm

.section .text.init, "ax"
.globl _start
_start:
  la   t6, trap
  csrw mtvec, t6

  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, 0x1f
  csrw pmpcfg0, t0

  la   t0, hs_entry
  csrw mepc, t0
  li   t1, MSTATUS_MPP_MASK
  csrc mstatus, t1
  li   t1, MSTATUS_MPP_S
  csrs mstatus, t1
  mret

hs_entry:
  la   t6, trap
  csrw stvec, t6

  li   t0, HEDELEG_18_19
  csrw CSR_HEDELEG, t0
  csrr s0, CSR_HEDELEG

  and  s0, s0, t0
  bne  s0, t0, fail_masked

  csrw CSR_HEDELEG, zero
  EXIT 0

fail_masked:
  EXIT 61

trap:
  csrr s1, mcause
  EXIT 62

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0
.globl fromhost
fromhost:
  .dword 0

.option pop
