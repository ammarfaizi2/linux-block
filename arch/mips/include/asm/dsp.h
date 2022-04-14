/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 Mips Technologies
 * Author: Chris Dearman, chris@mips.com derived from fpu.h
 */
#ifndef _ASM_DSP_H
#define _ASM_DSP_H

#include <asm/cpu.h>
#include <asm/cpu-features.h>
#include <asm/hazards.h>
#include <asm/mipsregs.h>

#define DSP_DEFAULT	0x00000000
#define DSP_MASK	0x3f

#define __enable_dsp_hazard()						\
do {									\
	asm("_ehb");							\
} while (0)

static inline void __init_dsp(void)
{
	mthi1(0);
	mtlo1(0);
	mthi2(0);
	mtlo2(0);
	mthi3(0);
	mtlo3(0);
	wrdsp(DSP_DEFAULT, DSP_MASK);
}

static inline void init_dsp(void)
{
	if (cpu_has_dsp)
		__init_dsp();
}

#define __save_dsp(tsk)							\
do {									\
	task_thread(tsk).dsp.dspr[0] = mfhi1();				\
	task_thread(tsk).dsp.dspr[1] = mflo1();				\
	task_thread(tsk).dsp.dspr[2] = mfhi2();				\
	task_thread(tsk).dsp.dspr[3] = mflo2();				\
	task_thread(tsk).dsp.dspr[4] = mfhi3();				\
	task_thread(tsk).dsp.dspr[5] = mflo3();				\
	task_thread(tsk).dsp.dspcontrol = rddsp(DSP_MASK);			\
} while (0)

#define save_dsp(tsk)							\
do {									\
	if (cpu_has_dsp)						\
		__save_dsp(tsk);					\
} while (0)

#define __restore_dsp(tsk)						\
do {									\
	mthi1(task_thread(tsk).dsp.dspr[0]);					\
	mtlo1(task_thread(tsk).dsp.dspr[1]);					\
	mthi2(task_thread(tsk).dsp.dspr[2]);					\
	mtlo2(task_thread(tsk).dsp.dspr[3]);					\
	mthi3(task_thread(tsk).dsp.dspr[4]);					\
	mtlo3(task_thread(tsk).dsp.dspr[5]);					\
	wrdsp(task_thread(tsk).dsp.dspcontrol, DSP_MASK);			\
} while (0)

#define restore_dsp(tsk)						\
do {									\
	if (cpu_has_dsp)						\
		__restore_dsp(tsk);					\
} while (0)

#define __get_dsp_regs(tsk)						\
({									\
	if (tsk == current)						\
		__save_dsp(current);					\
									\
	task_thread(tsk).dsp.dspr;						\
})

#endif /* _ASM_DSP_H */
