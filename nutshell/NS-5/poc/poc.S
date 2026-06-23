/*
 * PTW access fault is misclassified and can cross a trap-delegation boundary
 *
 * M-mode delegates load page faults to S-mode but retains load access faults.
 * A translated S-mode load then triggers a page-table-walk touch of physical
 * page 0 by installing a valid non-leaf root PTE with PPN=0.
 *
 * Correct behavior:
 *   cause 5 (Load access fault) is retained in M-mode.
 *
 * Vulnerable behavior:
 *   the PTW failure is misreported as cause 13 (Load page fault), so the trap
 *   is delegated into S-mode and bypasses the M-mode policy point.
 */

.option push
.option norelax
.option norvc

.equ SATP_SV39,             0x8000000000000000
.equ MSTATUS_MPP_MASK,      0x00001800
.equ MSTATUS_MPP_S,         0x00000800

.equ PTE_V,                 0x001
.equ PTE_R,                 0x002
.equ PTE_W,                 0x004
.equ PTE_X,                 0x008
.equ PTE_A,                 0x040
.equ PTE_D,                 0x080
.equ PTE_RWXAD,             (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)

.equ MY_VA,                 0x40201010
.equ ROOT_PTW_INDEX,        ((MY_VA >> 30) & 0x1ff)
.equ TEXT_PA_BASE,          0x80000000
.equ ROOT_CODE_INDEX,       ((TEXT_PA_BASE >> 30) & 0x1ff)
.equ ROOT_CODE_PTE,         (((TEXT_PA_BASE >> 12) << 10) | PTE_RWXAD)

.equ CAUSE_LD_ACCESS,       5
.equ CAUSE_LD_PAGE,         13
.equ MEDELEG_LOAD_PAGE,     (1 << 13)

.macro M_EXIT code
  csrw satp, zero
  sfence.vma x0, x0
  li   a0, \code
  la   t5, tohost
  li   t6, (((\code) * 2) + 1)
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
1:
  j 1b
.endm

.macro S_EXIT code
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
  la   t0, s_trap
  csrw stvec, t0

  csrw satp, zero
  csrw mideleg, zero
  li   t0, MEDELEG_LOAD_PAGE
  csrw medeleg, t0

  /* root_pt[1] = valid non-leaf with PPN=0 -> PTW touches physical page 0. */
  la   t0, root_pt
  li   t1, PTE_V
  sd   t1, (ROOT_PTW_INDEX * 8)(t0)

  /* root_pt[2] = 1-GiB identity-ish executable mapping for the S-mode code. */
  li   t1, ROOT_CODE_PTE
  sd   t1, (ROOT_CODE_INDEX * 8)(t0)

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
  la   t0, s_entry
  csrw mepc, t0
  mret

  M_EXIT 41

.align 2
s_entry:
  li   a0, MY_VA

.globl load_site
load_site:
  ld   t2, 0(a0)

  /* Returning here means the PTW failure was missed entirely. */
  S_EXIT 34

.align 2
m_trap:
  csrr t0, mcause
  li   t1, CAUSE_LD_ACCESS
  bne  t0, t1, fail_m_wrong_cause

  csrr t0, mepc
  la   t1, load_site
  bne  t0, t1, fail_m_wrong_epc

  csrr t0, mtval
  li   t1, MY_VA
  bne  t0, t1, fail_m_wrong_mtval

  M_EXIT 0

fail_m_wrong_cause:
  M_EXIT 35

fail_m_wrong_epc:
  M_EXIT 36

fail_m_wrong_mtval:
  M_EXIT 37

.align 2
s_trap:
  csrr t0, scause
  li   t1, CAUSE_LD_PAGE
  bne  t0, t1, fail_s_wrong_cause

  csrr t0, sepc
  la   t1, load_site
  bne  t0, t1, fail_s_wrong_epc

  csrr t0, stval
  li   t1, MY_VA
  bne  t0, t1, fail_s_wrong_stval

  /*
   * Reaching the S-mode handler at all is the security failure: the PTW event
   * was misclassified into a delegated page fault instead of a retained access
   * fault.
   */
  S_EXIT 31

fail_s_wrong_cause:
  S_EXIT 32

fail_s_wrong_epc:
  S_EXIT 33

fail_s_wrong_stval:
  S_EXIT 38

.section .data.pt, "aw"
.align 12
root_pt:
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
