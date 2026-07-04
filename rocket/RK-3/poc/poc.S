.option push
.option norelax
.option norvc

/*
 * Rocket RK-3 security PoC:
 *   a VS guest reads sstatus immediately after HS enters VS with
 *   hstatus.SPV=1. The guest-visible vsstatus state is clean/initial, while
 *   HS host sstatus is dirty. If the VS read exposes the HS FS/SD view, the
 *   PoC stores the observed value in an attacker-visible buffer and exits 31.
 */

.equ CSR_VSSTATUS,       0x200
.equ CSR_VSSCRATCH,      0x240
.equ CSR_VSATP,          0x280
.equ CSR_HSTATUS,        0x600
.equ CSR_HEDELEG,        0x602
.equ CSR_HIDELEG,        0x603
.equ CSR_HGATP,          0x680

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

.equ HOST_SSCRATCH_VAL,  0x1111
.equ GUEST_SSCRATCH_VAL, 0x2222
.equ LEAK_MARKER,        0x524b330000000031

.equ CAUSE_ILLEGAL,      2

.macro EXIT code
  li   a0, \code
  j    report_code
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
  csrw satp, zero
  csrw CSR_VSATP, zero
  csrw CSR_HGATP, zero
  csrw CSR_HEDELEG, zero
  csrw CSR_HIDELEG, zero

  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, PMP_RWX_NAPOT
  csrw pmpcfg0, t0

  csrr t0, misa
  li   t1, MISA_H
  and  t0, t0, t1
  beqz t0, no_h_extension

  /* Host-private marker: HS sstatus would report FS=Dirty and SD=1. */
  li   t0, STATUS_FS_MASK
  csrc mstatus, t0
  li   t0, STATUS_FS_DIRTY
  csrs mstatus, t0

  /* Control pair: generic S/VS CSR remapping must use vsscratch in VS. */
  li   t0, HOST_SSCRATCH_VAL
  csrw sscratch, t0
  li   t0, GUEST_SSCRATCH_VAL
  csrw CSR_VSSCRATCH, t0

  /* Guest-visible state: a correct VS sstatus read reports clean/initial. */
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

  la   t0, vs_entry
  csrw sepc, t0
  sret

  EXIT 94

.align 2
.globl vs_entry
vs_entry:
  csrr s4, sscratch
  la   t2, observed_sscratch
  sd   s4, 0(t2)
  li   t0, GUEST_SSCRATCH_VAL
  bne  s4, t0, fail_sscratch_alias

  csrr s0, sstatus
  la   t2, observed_sstatus
  sd   s0, 0(t2)

  li   t0, STATUS_FS_MASK
  and  t1, s0, t0
  li   t2, STATUS_FS_INITIAL
  beq  t1, t2, check_clean_sd

  li   t2, STATUS_FS_DIRTY
  beq  t1, t2, leak_host_status
  EXIT 81

check_clean_sd:
  li   t0, STATUS_SD
  and  t1, s0, t0
  bnez t1, leak_host_status
  EXIT 0

leak_host_status:
  la   t0, attacker_buffer
  sd   s0, 0(t0)
  li   t1, LEAK_MARKER
  sd   t1, 8(t0)
  li   a0, 31
  j    security_report_code

m_trap:
  csrr s1, mcause
  csrr s2, mepc
  csrr s3, mtval
  la   t0, trap_snapshot
  sd   s0, 0(t0)
  sd   s1, 8(t0)
  sd   s2, 16(t0)
  sd   s3, 24(t0)

  li   t1, CAUSE_ILLEGAL
  beq  s1, t1, fail_illegal
  addi a0, s1, 120
  j    report_code

no_h_extension:
  EXIT 91

fail_sscratch_alias:
  EXIT 83

fail_illegal:
  EXIT 92

report_code:
  la   t0, tohost
  slli t1, a0, 1
  ori  t1, t1, 1
  sd   t1, 0(t0)
  fence
1:
  j 1b

security_report_code:
  la   t0, tohost
  slli t1, a0, 1
  ori  t1, t1, 1
  sd   t1, 0(t0)
  fence
1:
  j 1b

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0

.globl fromhost
fromhost:
  .dword 0

.globl observed_sscratch
observed_sscratch:
  .dword 0

.globl observed_sstatus
observed_sstatus:
  .dword 0

.globl attacker_buffer
attacker_buffer:
  .dword 0
  .dword 0

.globl trap_snapshot
trap_snapshot:
  .dword 0
  .dword 0
  .dword 0
  .dword 0

.option pop
