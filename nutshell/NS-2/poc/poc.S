.option push
.option norelax
.option norvc

.equ HIGH_TAG,          0x2000000000000000
.equ MSTATUS_MPP_MASK,  0x00001800
.equ MSTATUS_MPP_S,     0x00000800
.equ CAUSE_ECALL_S,     9

.macro EXIT code
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
  csrw medeleg, zero
  csrw mideleg, zero
  csrw satp, zero

  /*
   * Let a lower-privileged stage prepare the low-alias payload first.
   * The later M-mode trap will be redirected to this buffer only on a core
   * that truncates mtvec during trap-target formation.
   */
  li   t0, MSTATUS_MPP_MASK
  csrc mstatus, t0
  li   t0, MSTATUS_MPP_S
  csrs mstatus, t0
  la   t0, s_prepare_payload
  csrw mepc, t0
  mret

  EXIT 41

.align 2
s_prepare_payload:
  la   s0, payload_template
  la   s1, payload_buf

  ld   t0, 0(s0)
  sd   t0, 0(s1)
  ld   t0, 8(s0)
  sd   t0, 8(s1)
  ld   t0, 16(s0)
  sd   t0, 16(s1)
  fence rw, rw
  fence.i

  /* Return to the trusted M-mode handler first. */
  ecall
  EXIT 42

.align 2
m_trap:
  csrr t0, mcause
  li   t1, CAUSE_ECALL_S
  beq  t0, t1, after_s_prepare
  EXIT 43

after_s_prepare:
  la   t0, payload_buf
  li   t1, HIGH_TAG
  or   t0, t0, t1
  csrw mtvec, t0

  csrr t2, mtvec
  bne  t2, t0, fail_mtvec_readback

  /*
   * Correct core: trap entry starts at HIGH_TAG|payload_buf.
   * Vulnerable NutShell: upper bits are dropped and execution begins at the
   * attacker-prepared low alias payload_buf.
   */
  ecall

  EXIT 44

fail_mtvec_readback:
  EXIT 45

.section .payload.template, "a"
.align 3
payload_template:
  .word 0x80001f37   /* lui  t5, 0x80001        -> tohost */
  .word 0x03f00f93   /* li   t6, 63             -> EXIT 31 */
  .word 0x01ff3023   /* sd   t6, 0(t5)          */
  .word 0x0ff0000f   /* fence                   */
  .word 0x0005006b   /* trap terminator         */
  .word 0x0000006f   /* j    .                  */

.section .data.payload, "aw"
.align 3
payload_buf:
  .zero 24

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0
.globl fromhost
fromhost:
  .dword 0

.option pop
