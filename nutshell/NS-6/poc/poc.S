/*
 * Misaligned Sv39 1-GiB leaf PTE is accepted
 *
 * A root-level leaf maps a 1-GiB page. Its lower PPN fields are deliberately
 * nonzero, so the superpage physical address is insufficiently aligned.
 * Correct behavior is a load page fault. NutShell's PTW appears to omit the
 * required lower-PPN alignment check and completes the load.
 */
.option push
.option norelax
.option norvc

.equ SATP_SV39,        0x8000000000000000
.equ MSTATUS_MPP_MASK, 0x00001800
.equ MSTATUS_MPP_S,    0x00000800
.equ MSTATUS_MPRV,     0x00020000
.equ PTE_V,            0x001
.equ PTE_R,            0x002
.equ PTE_A,            0x040
.equ PTE_D,            0x080
.equ PTE_RAD,          (PTE_V | PTE_R | PTE_A | PTE_D)
.equ CAUSE_LD_PF,      13
.equ CANARY,           0x1122334455667788

.macro EXIT code
  li   t4, MSTATUS_MPRV
  csrc mstatus, t4
  csrw satp, zero
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
  la   t0, trap_entry
  csrw mtvec, t0
  csrw medeleg, zero
  csrw mideleg, zero
  csrw satp, zero

  /* root_pt[1] is a root-level leaf. Force PPN[0] bit 0 = 1. */
  la   t0, root_pt
  la   t1, bad_data
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_RAD
  li   t2, (1 << 10)         /* PTE bit 10 == PPN[0] bit 0. */
  or   t1, t1, t2
  sd   t1, 8(t0)             /* VPN[2] = 1. */

  la   t0, root_pt
  srli t0, t0, 12
  li   t1, SATP_SV39
  or   t0, t0, t1
  csrw satp, t0
  sfence.vma x0, x0

  li   t0, MSTATUS_MPP_MASK
  csrc mstatus, t0
  li   t0, MSTATUS_MPP_S
  csrs mstatus, t0
  li   t0, MSTATUS_MPRV
  csrs mstatus, t0

  /* Build a VPN[2]=1 VA whose low 30 bits select bad_data. */
  la   t0, bad_data
  li   t1, 0x3fffffff
  and  a0, t0, t1
  li   t1, 0x40000000
  or   a0, a0, t1

.globl load_site
load_site:
  ld   t2, 0(a0)

  li   t3, CANARY
  beq  t2, t3, fail_misaligned_superpage_accepted
  EXIT 32

trap_entry:
  csrr t0, mcause
  li   t1, CAUSE_LD_PF
  bne  t0, t1, fail_trap
  csrr t0, mepc
  la   t1, load_site
  bne  t0, t1, fail_trap
  csrr t0, mtval
  bne  t0, a0, fail_trap
  EXIT 0

fail_misaligned_superpage_accepted:
  EXIT 31
fail_trap:
  EXIT 33

.section .data.pt, "aw"
.align 12
root_pt:
  .zero 4096

.section .data, "aw"
.align 12
bad_data:
  .dword CANARY

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0
.globl fromhost
fromhost:
  .dword 0

.option pop
