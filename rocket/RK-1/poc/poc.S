/*
 * Rocket PMP reserved reset/readback encoding self-oracle.
 *
 * PMP cfg R/W/X is a collective WARL field, and R=0/W=1 is a reserved
 * encoding. This test reads pmpcfg0 after the BootROM jump stub and fails
 * if any PMP cfg byte exposes the reserved R/W pattern.
 *
 * Run on the official Rocket Verilator emulator with a fixed seed.
 * Expected on affected DUT: EXIT 93.
 */
.option push
.option norelax
.option norvc

.macro EXIT code
  li   a0, \code
  la   t5, tohost
  li   t6, (((\code) << 1) | 1)
  sd   t6, 0(t5)
  fence
  .word 0x0005006b
.endm

.section .text.init, "ax"
.globl _start
_start:
  csrr s0, pmpcfg0

  mv   t0, s0
  li   t1, 8

check_loop:
  andi t2, t0, 0xff      /* current pmpcfg byte */
  andi t3, t2, 0x03      /* R/W bits */
  li   t4, 0x02          /* R=0, W=1 reserved */
  beq  t3, t4, fail_reserved_rw

  srli t0, t0, 8
  addi t1, t1, -1
  bnez t1, check_loop

  EXIT 0

fail_reserved_rw:
  EXIT 93

.section .tohost, "aw"
.align 3
.globl tohost
tohost:
  .dword 0
.globl fromhost
fromhost:
  .dword 0

.option pop
