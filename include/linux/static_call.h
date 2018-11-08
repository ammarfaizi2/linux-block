/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STATIC_CALL_H
#define _LINUX_STATIC_CALL_H

/*
 * Static call support
 *
 * Static calls use code patching to hard-code function pointers into direct
 * branch instructions.  They give the flexibility of function pointers, but
 * with improved performance.  This is especially important for cases where
 * retpolines would otherwise be used, as retpolines can significantly impact
 * performance.
 *
 *
 * API overview:
 *
 *   DECLARE_STATIC_CALL(key, func);
 *   DEFINE_STATIC_CALL(key, func);
 *   static_call(key, args...);
 *   static_call_update(key, func);
 *
 *
 * Usage example:
 *
 *   # Start with the following functions (with identical prototypes):
 *   int func_a(int arg1, int arg2);
 *   int func_b(int arg1, int arg2);
 *
 *   # Define a 'my_key' reference, associated with func_a() by default
 *   DEFINE_STATIC_CALL(my_key, func_a);
 *
 *   # Call func_a()
 *   static_call(my_key, arg1, arg2);
 *
 *   # Update 'my_key' to point to func_b()
 *   static_call_update(my_key, func_b);
 *
 *   # Call func_b()
 *   static_call(my_key, arg1, arg2);
 *
 *
 * Implementation details:
 *
 * There are three different implementations:
 *
 * 1) Optimized static calls (patched call sites)
 *
 *    This requires objtool, which detects all the static_call() sites and
 *    annotates them in the '.static_call_sites' section.  By default, the call
 *    sites will call into a temporary per-key trampoline which has an indirect
 *    branch to the current destination function associated with the key.
 *    During system boot (or module init), all call sites are patched to call
 *    their destination functions directly.  Updates to a key will patch all
 *    call sites associated with that key.
 *
 * 2) Unoptimized static calls (patched trampolines)
 *
 *    Each static_call() site calls into a permanent trampoline associated with
 *    the key.  The trampoline has a direct branch to the default function.
 *    Updates to a key will modify the direct branch in the key's trampoline.
 *
 * 3) Generic implementation
 *
 *    This is the default implementation if the architecture hasn't implemented
 *    CONFIG_HAVE_STATIC_CALL_[UN]OPTIMIZED.  In this case, a basic
 *    function pointer is used.
 */

#include <linux/types.h>
#include <linux/cpu.h>
#include <linux/static_call_types.h>

#if defined(CONFIG_HAVE_STATIC_CALL_OPTIMIZED) || \
    defined(CONFIG_HAVE_STATIC_CALL_UNOPTIMIZED)

#include <asm/static_call.h>

extern void arch_static_call_transform(unsigned long insn, void *dest);

#endif /* CONFIG_HAVE_STATIC_CALL_[UN]OPTIMIZED */

#ifdef CONFIG_HAVE_STATIC_CALL_OPTIMIZED
/* Optimized implementation */

struct static_call_mod {
	struct list_head list;
	struct module *mod; /* NULL means vmlinux */
	struct static_call_site *sites;
};

struct static_call_key {
	/*
	 * This field should always be first because the trampolines expect it.
	 * This points to the current call destination.
	 */
	void *func;

	/*
	 * List of modules (including vmlinux) and the call sites which need to
	 * be patched for this key.
	 */
	struct list_head site_mods;
};

extern void __static_call_update(struct static_call_key *key, void *func);
extern void arch_static_call_poison_tramp(unsigned long insn);

#define DECLARE_STATIC_CALL(key, func)					\
	extern struct static_call_key key;				\
	extern typeof(func) STATIC_CALL_TRAMP(key);			\
	/* Preserve the ELF symbol so objtool can access it: */		\
	__ADDRESSABLE(key)

#define DEFINE_STATIC_CALL(key, _func)					\
	DECLARE_STATIC_CALL(key, _func);				\
	struct static_call_key key = {					\
		.func = _func,						\
		.site_mods = LIST_HEAD_INIT(key.site_mods),		\
	};								\
	ARCH_STATIC_CALL_TEMPORARY_TRAMP(key)

#define static_call(key, args...) STATIC_CALL_TRAMP(key)(args)

#define static_call_update(key, func)					\
({									\
	BUILD_BUG_ON(!__same_type(typeof(func), typeof(STATIC_CALL_TRAMP(key)))); \
	__static_call_update(&key, func);				\
})

#define EXPORT_STATIC_CALL(key)						\
	EXPORT_SYMBOL(key);						\
	EXPORT_SYMBOL(STATIC_CALL_TRAMP(key))

#define EXPORT_STATIC_CALL_GPL(key)					\
	EXPORT_SYMBOL_GPL(key);						\
	EXPORT_SYMBOL_GPL(STATIC_CALL_TRAMP(key))


#elif defined(CONFIG_HAVE_STATIC_CALL_UNOPTIMIZED)
/* Unoptimized implementation */

#define DECLARE_STATIC_CALL(key, func)					\
	extern typeof(func) STATIC_CALL_TRAMP(key)

#define DEFINE_STATIC_CALL(key, func)					\
	DECLARE_STATIC_CALL(key, func);					\
	ARCH_STATIC_CALL_TRAMP(key, func)

#define static_call(key, args...) STATIC_CALL_TRAMP(key)(args)

#define static_call_update(key, func)					\
({									\
	BUILD_BUG_ON(!__same_type(func, STATIC_CALL_TRAMP(key)));	\
	cpus_read_lock();						\
	arch_static_call_transform((unsigned long)STATIC_CALL_TRAMP(key),\
				   func);				\
	cpus_read_unlock();						\
})

#define EXPORT_STATIC_CALL(key)						\
	EXPORT_SYMBOL(STATIC_CALL_TRAMP(key))

#define EXPORT_STATIC_CALL_GPL(key)					\
	EXPORT_SYMBOL_GPL(STATIC_CALL_TRAMP(key))


#else /* Generic implementation */

#define DECLARE_STATIC_CALL(key, func)					\
	extern typeof(func) *key

#define DEFINE_STATIC_CALL(key, func)					\
	typeof(func) *key = func

#define static_call(key, args...)					\
	key(args)

#define static_call_update(key, func)					\
	WRITE_ONCE(key, func)

#define EXPORT_STATIC_CALL(key) EXPORT_SYMBOL(key)
#define EXPORT_STATIC_CALL_GPL(key) EXPORT_SYMBOL_GPL(key)

#endif /* CONFIG_HAVE_STATIC_CALL_OPTIMIZED */

#endif /* _LINUX_STATIC_CALL_H */
