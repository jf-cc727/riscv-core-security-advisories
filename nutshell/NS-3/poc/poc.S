/*
 * Translated U-mode store may bypass a physical write boundary
 *
 * M-mode installs a PMP entry that denies all S/U access to the 4-KiB page
 * containing protected_data, while a later PMP entry allows everything else.
 * The page table then maps TEST_VA to that same physical page with a valid
 * user-writable leaf.
 *
 * Correct behavior is a Store/AMO access fault at the translated store.
 * If NutShell lets the store retire, U-mode reaches ECALL and M-mode reads
 * the protected physical canary directly to see whether the denied write
 * changed memory.
 */
.option push
.option norelax
.option norvc

.equ SATP_SV39,              0x8000000000000000

.equ MSTATUS_MPP_MASK,       0x00001800

.equ PMP_NAPOT,              0x18
.equ PMP_R,                  0x01
.equ PMP_W,                  0x02
.equ PMP_X,                  0x04
.equ PMP_RWX_NAPOT,          (PMP_NAPOT | PMP_R | PMP_W | PMP_X)

.equ PTE_V,                  0x001
.equ PTE_R,                  0x002
.equ PTE_W,                  0x004
.equ PTE_X,                  0x008
.equ PTE_U,                  0x010
.equ PTE_A,                  0x040
.equ PTE_D,                  0x080
.equ PTE_TABLE,              PTE_V
.equ PTE_RWUAD,              (PTE_V | PTE_R | PTE_W | PTE_U | PTE_A | PTE_D)
.equ PTE_RXUAD,              (PTE_V | PTE_R | PTE_X | PTE_U | PTE_A | PTE_D)

.equ TEST_VA,                0x0000000040000000
.equ TEXT_PA_BASE,           0x80000000
.equ ROOT_TEST_INDEX,        ((TEST_VA >> 30) & 0x1ff)
.equ L1_TEST_INDEX,          ((TEST_VA >> 21) & 0x1ff)
.equ L0_TEST_INDEX,          ((TEST_VA >> 12) & 0x1ff)
.equ ROOT_TEXT_INDEX,        ((TEXT_PA_BASE >> 30) & 0x1ff)
.equ ROOT_TEXT_PTE,          (((TEXT_PA_BASE >> 12) << 10) | PTE_RXUAD)

.equ MCAUSE_STORE_ACCESS,    7
.equ MCAUSE_ECALL_FROM_U,    8

.equ OLD_VALUE,              0x1122334455667788
.equ NEW_VALUE,              0xdeadbeefcafef00d

.macro EXIT code
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

.section .text.init, "ax"
.globl _start
_start:
  la   t0, trap_entry
  csrw mtvec, t0
  csrw medeleg, zero
  csrw mideleg, zero
  csrw satp, zero

  /* Seed the protected physical sentinel. */
  la   t0, protected_data
  li   t1, OLD_VALUE
  sd   t1, 0(t0)

  /*
   * PMP0: no permissions on the 4-KiB page containing protected_data.
   * PMP1: allow everything else so U-mode can still fetch and run.
   */
  la   t0, protected_data
  srli t0, t0, 2
  li   t1, 0x1ff
  or   t0, t0, t1
  csrw pmpaddr0, t0
  li   t0, -1
  csrw pmpaddr1, t0
  li   t0, (PMP_RWX_NAPOT << 8) | PMP_NAPOT
  csrw pmpcfg0, t0

  /* root_pt[ROOT_TEST_INDEX] -> l1_pt */
  la   t0, root_pt
  la   t1, l1_pt
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_TABLE
  sd   t1, (ROOT_TEST_INDEX * 8)(t0)

  /* root_pt[ROOT_TEXT_INDEX] -> 1-GiB executable user mapping for code */
  li   t1, ROOT_TEXT_PTE
  sd   t1, (ROOT_TEXT_INDEX * 8)(t0)

  /* l1_pt[L1_TEST_INDEX] -> l0_pt */
  la   t0, l1_pt
  la   t1, l0_pt
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_TABLE
  sd   t1, (L1_TEST_INDEX * 8)(t0)

  /* l0_pt[L0_TEST_INDEX] -> protected_data page as a valid user leaf */
  la   t0, l0_pt
  la   t1, protected_data
  srli t1, t1, 12
  slli t1, t1, 10
  ori  t1, t1, PTE_RWUAD
  sd   t1, (L0_TEST_INDEX * 8)(t0)

  la   t0, root_pt
  srli t0, t0, 12
  li   t1, SATP_SV39
  or   t0, t0, t1
  csrw satp, t0
  sfence.vma x0, x0

  li   t0, MSTATUS_MPP_MASK
  csrc mstatus, t0
  la   t0, u_store
  csrw mepc, t0
  mret

  EXIT 41

.align 2
u_store:
  li   a0, TEST_VA
  li   a1, NEW_VALUE

.globl store_site
store_site:
  sd   a1, 0(a0)
  fence rw, rw
ecall_site:
  ecall

.align 2
trap_entry:
  csrr t0, mcause
  li   t1, MCAUSE_STORE_ACCESS
  beq  t0, t1, handle_store_fault
  li   t1, MCAUSE_ECALL_FROM_U
  beq  t0, t1, handle_post_store_ecall
  EXIT 43

handle_store_fault:
  csrr t0, mepc
  la   t1, store_site
  bne  t0, t1, fail_bad_trap_metadata
  csrr t0, mtval
  li   t1, TEST_VA
  bne  t0, t1, fail_bad_trap_metadata
  EXIT 0

handle_post_store_ecall:
  csrr t0, mepc
  la   t1, ecall_site
  bne  t0, t1, fail_bad_trap_metadata
  csrw satp, zero
  sfence.vma x0, x0
  la   t0, protected_data
  ld   t1, 0(t0)
  li   t2, NEW_VALUE
  beq  t1, t2, fail_protected_write_committed
  EXIT 42

fail_protected_write_committed:
  EXIT 31

fail_bad_trap_metadata:
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

.section .data.protected, "aw"
.align 12
protected_data:
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
