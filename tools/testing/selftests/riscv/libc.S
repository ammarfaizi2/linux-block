# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2022 Rivos, Inc
# A C library

#if __riscv_xlen == 64
# define REG_S sd
#else
# define REG_S sw
#endif

.text
.global _start
_start:
.option push
.option norelax
	la gp, __global_pointer$
.option pop

	la sp, stack

	la t0, heap
	la t1, brk
	REG_S t0, 0(t1)

	li a0, 0
	li a1, 0

	call main
	
	li a7, 93
	ecall

1:
	j 1b

.data
brk:
	.long 0

.global heap
heap:
.rep 65536
.byte 0
.endr
.global stack
stack:
