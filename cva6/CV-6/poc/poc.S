/*
 * CVA6 VS FP-state lazy-save security PoC.
 *
 * Correct behavior:
 *   After a VS-mode FP register write, the V-visible status read used by a
 *   context manager reports both FS=Dirty and SD=1.  The PoC exits 0 before
 *   exposing the FP register file to the next context.
 *
 * Vulnerable CVA6 behavior:
 *   Context A writes a secret marker into ft0 and immediately reaches a
 *   VS-mode lazy-save scheduler.  The scheduler observes FS=Dirty but stale
 *   SD=0, treats that as "no extended VS state is dirty", skips saving and
 *   clearing A's FP state, then runs context B.  Context B reads ft0 and sees
 *   A's marker, proving cross-context FP-state exposure.  The PoC exits 31.
 */
.option push
.option norelax
.option norvc

.equ CSR_VSSTATUS,       0x200
.equ CSR_VSATP,          0x280
.equ CSR_HSTATUS,        0x600
.equ CSR_HEDELEG,        0x602
.equ CSR_HIDELEG,        0x603
.equ CSR_HGATP,          0x680

.equ MISA_F,             0x20
.equ MISA_H,             0x80
.equ PMP_RWX_NAPOT,      0x1f
.equ MSTATUS_MPP_MASK,   0x00001800
.equ MSTATUS_MPP_S,      0x00000800
.equ HSTATUS_SPV,        0x00000080
.equ SSTATUS_SPP,        0x00000100

.equ STATUS_FS_MASK,     0x00006000
.equ STATUS_FS_INITIAL,  0x00002000
.equ STATUS_FS_DIRTY,    0x00006000
.equ STATUS_SD,          0x8000000000000000

.equ A_SECRET_WORD,      0x13572468
.equ B_CLOBBER_WORD,     0x24681357

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
  csrw CSR_VSATP, zero
  csrw CSR_HGATP, zero

  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, PMP_RWX_NAPOT
  csrw pmpcfg0, t0

  csrr t0, misa
  li   t1, MISA_H
  and  t2, t0, t1
  beqz t2, no_h_extension
  li   t1, MISA_F
  and  t2, t0, t1
  beqz t2, no_f_extension

  li   t0, STATUS_FS_MASK
  csrc mstatus, t0
  li   t0, STATUS_FS_DIRTY
  csrs mstatus, t0

  csrw CSR_VSSTATUS, zero
  li   t0, STATUS_FS_INITIAL
  csrs CSR_VSSTATUS, t0

  li   t0, MSTATUS_MPP_MASK
  csrc mstatus, t0
  li   t0, MSTATUS_MPP_S
  csrs mstatus, t0
  la   t0, hs_entry
  csrw mepc, t0
  mret

  EXIT 93

.align 2
hs_entry:
  csrw CSR_HSTATUS, zero
  li   t0, HSTATUS_SPV
  csrs CSR_HSTATUS, t0

  li   t0, SSTATUS_SPP
  csrs sstatus, t0

  la   t0, vs_context_a
  csrw sepc, t0
  sret

  EXIT 94

.align 2
.globl vs_context_a
vs_context_a:
  csrr s1, sstatus
  li   t0, STATUS_FS_MASK
  and  t1, s1, t0
  li   t2, STATUS_FS_INITIAL
  bne  t1, t2, fail_guest_setup_fs
  li   t0, STATUS_SD
  and  t1, s1, t0
  bnez t1, fail_guest_setup_sd

  li   t0, A_SECRET_WORD
.globl context_a_fp_write_site
context_a_fp_write_site:
  fmv.w.x ft0, t0

.globl lazy_save_scheduler
lazy_save_scheduler:
  csrr s2, sstatus
  la   t0, scheduler_observed_sstatus
  sd   s2, 0(t0)

  li   t0, STATUS_FS_MASK
  and  t1, s2, t0
  li   t2, STATUS_FS_DIRTY
  bne  t1, t2, fail_scheduler_fs_not_dirty

  li   t0, STATUS_SD
  and  t1, s2, t0
  bnez t1, pass_scheduler_saw_dirty_summary

  li   t0, 1
  la   t1, scheduler_skipped_save
  sd   t0, 0(t1)

  j    vs_context_b

pass_scheduler_saw_dirty_summary:
  EXIT 0

.align 2
.globl vs_context_b
vs_context_b:
  fmv.x.w t0, ft0
  la   t1, context_b_observed_fp_word
  sd   t0, 0(t1)

  li   t1, A_SECRET_WORD
  beq  t0, t1, context_b_leaked_a_state

  li   t1, B_CLOBBER_WORD
  beq  t0, t1, fail_context_b_already_clean
  EXIT 33

context_b_leaked_a_state:
  li   t0, B_CLOBBER_WORD
  fmv.w.x ft0, t0
  EXIT 31

.align 2
m_trap:
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

no_h_extension:
  EXIT 91
no_f_extension:
  EXIT 95
fail_guest_setup_fs:
  EXIT 83
fail_guest_setup_sd:
  EXIT 84
fail_scheduler_fs_not_dirty:
  EXIT 85
fail_context_b_already_clean:
  EXIT 32

.section .data, "aw"
.align 3
scheduler_observed_sstatus:
  .dword 0

.align 3
scheduler_skipped_save:
  .dword 0

.align 3
context_b_observed_fp_word:
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
