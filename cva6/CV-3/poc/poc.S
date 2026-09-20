/*
 * CVA6 documented medeleg[9] missing security PoC
 *
 * This models an M-mode compartment monitor that trusts CVA6's in-tree CSR
 * documentation: medeleg[31:0] is described as RW with one bit position per
 * synchronous exception. The monitor therefore configures medeleg[9] so that
 * S-mode ECALLs are handled by the S-mode syscall gate, not by the M-mode
 * security-violation path.
 *
 * Correct behavior under the documented CVA6 contract:
 *   S-mode ECALL traps horizontally to s_syscall_gate.
 *   The local S gate records S_GATE_MARKER and exits with code 0.
 *
 * Vulnerable CVA6 behavior:
 *   The CSR_MEDELEG writable mask omits ENV_CALL_SMODE.
 *   S-mode ECALL unexpectedly enters m_security_violation.
 *   The monitor records M_PANIC_MARKER and exits with code 31.
 */
.option push
.option norelax
.option norvc

.equ CAUSE_ECALL_S,       9

.equ MSTATUS_MPP_MASK,   0x00001800
.equ MSTATUS_MPP_S,      0x00000800
.equ PMP_RWX_NAPOT,      0x1f
.equ MEDELEG_ECALL_S,    0x00000200

.equ S_GATE_MARKER,      0x53474154454f4b21
.equ M_PANIC_MARKER,     0x4d50414e49432121

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
  la   t0, m_security_violation
  csrw mtvec, t0
  csrw mideleg, zero
  csrw satp, zero

  /* Open physical memory so the trap-routing test is not blocked by PMP. */
  li   t0, -1
  csrw pmpaddr0, t0
  li   t0, PMP_RWX_NAPOT
  csrw pmpcfg0, t0

  /*
   * Monitor trusts CVA6 documentation and routes S-mode ECALLs to the local
   * S-mode syscall gate.
   */
  li   t0, MEDELEG_ECALL_S
  csrw medeleg, t0

  la   t0, s_syscall_gate
  csrw stvec, t0

  csrr t0, mstatus
  li   t1, MSTATUS_MPP_MASK
  not  t1, t1
  and  t0, t0, t1
  li   t1, MSTATUS_MPP_S
  or   t0, t0, t1
  csrw mstatus, t0

  la   t0, s_tenant_entry
  csrw mepc, t0
  mret

s_tenant_entry:
  csrw satp, zero

.globl s_ecall_site
s_ecall_site:
  ecall
  EXIT 32

s_syscall_gate:
  csrr t0, scause
  li   t1, CAUSE_ECALL_S
  bne  t0, t1, fail_s_gate_metadata

  csrr t0, sepc
  la   t1, s_ecall_site
  bne  t0, t1, fail_s_gate_metadata

  li   t0, S_GATE_MARKER
  la   t1, security_state
  sd   t0, 0(t1)
  EXIT 0

m_security_violation:
  csrr t0, mcause
  li   t1, CAUSE_ECALL_S
  bne  t0, t1, fail_m_gate_metadata

  csrr t0, mepc
  la   t1, s_ecall_site
  bne  t0, t1, fail_m_gate_metadata

  li   t0, M_PANIC_MARKER
  la   t1, security_state
  sd   t0, 0(t1)
  EXIT 31

fail_s_gate_metadata:
  EXIT 40

fail_m_gate_metadata:
  EXIT 41

.section .data, "aw"
.align 3
security_state:
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
