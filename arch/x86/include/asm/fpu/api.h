/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 1994 Linus Torvalds
 *
 * Pentium III FXSR, SSE support
 * General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 * x86-64 work by Andi Kleen 2002
 */

#ifndef _ASM_X86_FPU_API_H
#define _ASM_X86_FPU_API_H
#include <linux/bottom_half.h>

#include <asm/fpu/types.h>

/*
 * Use kernel_fpu_begin/end() if you intend to use FPU in kernel context. It
 * disables preemption so be careful if you intend to use it for long periods
 * of time.
 * If you intend to use the FPU in irq/softirq you need to check first with
 * irq_fpu_usable() if it is possible.
 */

/* Kernel FPU states to initialize in kernel_fpu_begin_mask() */
#define KFPU_387	_BITUL(0)	/* 387 state will be initialized */
#define KFPU_MXCSR	_BITUL(1)	/* MXCSR will be initialized */

extern void kernel_fpu_begin_mask(unsigned int kfpu_mask);
extern void kernel_fpu_end(void);
extern bool irq_fpu_usable(void);
extern void fpregs_mark_activate(void);

/* Code that is unaware of kernel_fpu_begin_mask() can use this */
static inline void kernel_fpu_begin(void)
{
#ifdef CONFIG_X86_64
	/*
	 * Any 64-bit code that uses 387 instructions must explicitly request
	 * KFPU_387.
	 */
	kernel_fpu_begin_mask(KFPU_MXCSR);
#else
	/*
	 * 32-bit kernel code may use 387 operations as well as SSE2, etc,
	 * as long as it checks that the CPU has the required capability.
	 */
	kernel_fpu_begin_mask(KFPU_387 | KFPU_MXCSR);
#endif
}

/*
 * Use fpregs_lock() while editing CPU's FPU registers or fpu->fpstate.
 * A context switch will (and softirq might) save CPU's FPU registers to
 * fpu->fpstate.regs and set TIF_NEED_FPU_LOAD leaving CPU's FPU registers in
 * a random state.
 *
 * local_bh_disable() protects against both preemption and soft interrupts
 * on !RT kernels.
 *
 * On RT kernels local_bh_disable() is not sufficient because it only
 * serializes soft interrupt related sections via a local lock, but stays
 * preemptible. Disabling preemption is the right choice here as bottom
 * half processing is always in thread context on RT kernels so it
 * implicitly prevents bottom half processing as well.
 *
 * Disabling preemption also serializes against kernel_fpu_begin().
 */
static inline void fpregs_lock(void)
{
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		local_bh_disable();
	else
		preempt_disable();
}

static inline void fpregs_unlock(void)
{
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		local_bh_enable();
	else
		preempt_enable();
}

#ifdef CONFIG_X86_DEBUG_FPU
extern void fpregs_assert_state_consistent(void);
#else
static inline void fpregs_assert_state_consistent(void) { }
#endif

/*
 * Load the task FPU state before returning to userspace.
 */
extern void switch_fpu_return(void);

/*
 * Query the presence of one or more xfeatures. Works on any legacy CPU as well.
 *
 * If 'feature_name' is set then put a human-readable description of
 * the feature there as well - this can be used to print error (or success)
 * messages.
 */
extern int cpu_has_xfeatures(u64 xfeatures_mask, const char **feature_name);

/* Trap handling */
extern int  fpu__exception_code(struct fpu *fpu, int trap_nr);
extern void fpu_sync_fpstate(struct fpu *fpu);
extern void fpu_reset_from_exception_fixup(void);

/* Boot, hotplug and resume */
extern void fpu__init_cpu(void);
extern void fpu__init_system(struct cpuinfo_x86 *c);
extern void fpu__init_check_bugs(void);
extern void fpu__resume_cpu(void);

#ifdef CONFIG_MATH_EMULATION
extern void fpstate_init_soft(struct swregs_state *soft);
#else
static inline void fpstate_init_soft(struct swregs_state *soft) {}
#endif

/* State tracking */
DECLARE_PER_CPU(struct fpu *, fpu_fpregs_owner_ctx);

/* Process cleanup */
#ifdef CONFIG_X86_64
extern void fpstate_free(struct fpu *fpu);
#else
static inline void fpstate_free(struct fpu *fpu) { }
#endif

/* fpstate-related functions which are exported to KVM */
extern void fpstate_clear_xstate_component(struct fpstate *fps, unsigned int xfeature);

/* KVM specific functions */
extern bool fpu_alloc_guest_fpstate(struct fpu_guest *gfpu);
extern void fpu_free_guest_fpstate(struct fpu_guest *gfpu);
extern int fpu_swap_kvm_fpstate(struct fpu_guest *gfpu, bool enter_guest);
extern int __fpu_update_guest_features(struct fpu_guest *guest_fpu, u64 xcr0, u64 xfd);

/**
 * fpu_update_guest_xcr0 - Update guest XCR0 from XSETBV emulation
 * @guest_fpu:	Pointer to the guest FPU container
 * @xcr0:	Requested guest XCR0
 *
 * Has to be invoked before making the guest XCR0 update effective. The
 * function validates that the requested features are permitted and ensures
 * that @guest_fpu->fpstate is properly sized taking @guest_fpu->fpstate->xfd
 * into account.
 *
 * If @guest_fpu->fpstate is not the current tasks active fpstate then the
 * caller has to ensure that @guest_fpu->fpstate cannot be concurrently in
 * use, i.e. the guest restore case.
 *
 * Return:
 * 0		- Success
 * -EPERM	- Feature(s) not permitted
 * -EFAULT	- Resizing of fpstate failed
 */
static inline int fpu_update_guest_xcr0(struct fpu_guest *guest_fpu, u64 xcr0)
{
	return __fpu_update_guest_features(guest_fpu, xcr0, guest_fpu->fpstate->xfd);
}

/**
 * fpu_update_guest_xfd - Update guest XFD from MSR write emulation
 * @guest_fpu:	Pointer to the guest FPU container
 * @xcr0:	Current guest XCR0
 * @xfd:	Requested XFD value
 *
 * Has to be invoked to make the guest XFD update effective. The function
 * validates the XFD value and ensures that @guest_fpu->fpstate is properly
 * sized by taking @xcr0 into account.
 *
 * The caller must not modify @guest_fpu->fpstate->xfd or the XFD MSR
 * directly.
 *
 * If @guest_fpu->fpstate is not the current tasks active fpstate then the
 * caller has to ensure that @guest_fpu->fpstate cannot be concurrently in
 * use, i.e. the guest restore case.
 *
 * On success the buffer size is valid, @guest_fpu->fpstate.xfd == @xfd and
 * if the guest fpstate is active then MSR_IA32_XFD == @xfd.
 *
 * On failure the previous state is retained.
 *
 * Return:
 * 0		- Success
 * -ENOTSUPP	- XFD value not supported
 * -EFAULT	- Resizing of fpstate failed
 */
static inline int fpu_update_guest_xfd(struct fpu_guest *guest_fpu, u64 xcr0, u64 xfd)
{
	return __fpu_update_guest_features(guest_fpu, xcr0, xfd);
}

#ifdef CONFIG_X86_64
extern void fpu_sync_guest_vmexit_xfd_state(void);
#else
static inline void fpu_sync_guest_vmexit_xfd_state(void) { }
#endif

extern void fpu_copy_guest_fpstate_to_uabi(struct fpu_guest *gfpu, void *buf, unsigned int size, u32 pkru);
extern int fpu_copy_uabi_to_guest_fpstate(struct fpu_guest *gfpu, const void *buf, u64 xcr0, u32 *vpkru);

static inline void fpstate_set_confidential(struct fpu_guest *gfpu)
{
	gfpu->fpstate->is_confidential = true;
}

static inline bool fpstate_is_confidential(struct fpu_guest *gfpu)
{
	return gfpu->fpstate->is_confidential;
}

/* prctl */
struct task_struct;
extern long fpu_xstate_prctl(struct task_struct *tsk, int option, unsigned long arg2);

#endif /* _ASM_X86_FPU_API_H */
