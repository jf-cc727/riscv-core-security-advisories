/*
 * Lowest-level PTE with W=1,R=0 is accepted for a store
 *
 * RISC-V defines W=1,R=0 as an invalid PTE encoding. The NutShell PTW checks
 * this invalid combination only while it still believes the entry can be a
 * non-leaf at upper levels; the final-level permission path accepts V=1,W=1
 * as a writable leaf.
 */
.option push
.option norelax
.option norvc

.equ SATP_SV39,        0x8000000000000000
.equ MSTATUS_MPP_MASK, 0x00001800
.equ MSTATUS_MPP_S,    0x00000800
.equ MSTATUS_MPRV,     0x00020000
.equ PTE_V,            0x001
.equ PTE_W,            0x004
.equ PTE_A,            0x040
.equ PTE_D,            0x080
.equ PTE_TABLE,        PTE_V
.equ PTE_VWAD,         (PTE_V | PTE_W | PTE_A | PTE_D)
.equ MY_VA,            0x0000000040000000
.equ ROOT_INDEX,       ((MY_VA >> 30) & 0x1ff)
.equ L1_INDEX,         ((MY_VA >> 21) & 0x1ff)
.equ L0_INDEX,         ((MY_VA >> 12) & 0x1ff)
.equ CAUSE_ST_PF,      15
.equ OLD_VALUE,        0x1122334455667788
.equ NEW_VALUE,        0x8877665544332211

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

  la   t0, root_pt
  la   t1, l1_pt
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_TABLE
  sd   t1, (ROOT_INDEX * 8)(t0)

  la   t0, l1_pt
  la   t1, l0_pt
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_TABLE
  sd   t1, (L1_INDEX * 8)(t0)

  la   t0, l0_pt
  la   t1, bad_data
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_VWAD
  sd   t1, (L0_INDEX * 8)(t0)

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

  li   a0, MY_VA
  li   a1, NEW_VALUE
.globl store_site
store_site:
  sd   a1, 0(a0)

  /* If the store returned, inspect the physical target. */
  fence rw, rw
  li   t4, MSTATUS_MPRV
  csrc mstatus, t4
  csrw satp, zero
  sfence.vma x0, x0
  la   t0, bad_data
  ld   t1, 0(t0)
  beq  t1, a1, fail_write_only_leaf_accepted
  EXIT 32

trap_entry:
  csrr t0, mcause
  li   t1, CAUSE_ST_PF
  bne  t0, t1, fail_trap
  csrr t0, mepc
  la   t1, store_site
  bne  t0, t1, fail_trap
  csrr t0, mtval
  li   t1, MY_VA
  bne  t0, t1, fail_trap
  EXIT 0

fail_write_only_leaf_accepted:
  EXIT 31
fail_trap:
  EXIT 33

.section .data.pt, "aw"
.align 12
root_pt:
  .zero 4096
.align 12
l1_pt:
  .zero 4096
.align 12
l0_pt:
  .zero 4096

.section .data, "aw"
.align 12
bad_data:
  .dword OLD_VALUE

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0
.globl fromhost
fromhost:
  .dword 0

.option pop
