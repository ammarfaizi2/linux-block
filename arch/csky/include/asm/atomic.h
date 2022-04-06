/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_CSKY_ATOMIC_H
#define __ASM_CSKY_ATOMIC_H

#ifdef CONFIG_SMP
# include <asm-generic/atomic64.h>

#include <asm/cmpxchg.h>
#include <asm/barrier.h>

#define __atomic_acquire_fence()	__smp_acquire_fence()

#define __atomic_release_fence()	__smp_release_fence()

static __always_inline int arch_atomic_read(const atomic_t *v)
{
	return READ_ONCE(v->counter);
}
static __always_inline void arch_atomic_set(atomic_t *v, int i)
{
	WRITE_ONCE(v->counter, i);
}

#define ATOMIC_OP(op, asm_op, I)					\
static __always_inline							\
void arch_atomic_##op(int i, atomic_t *v)				\
{									\
	unsigned long tmp;						\
	__asm__ __volatile__ (						\
	"1:	ldex.w		%0, (%2)	\n"			\
	"	" #op "		%0, %1		\n"			\
	"	stex.w		%0, (%2)	\n"			\
	"	bez		%0, 1b		\n"			\
	: "=&r" (tmp)							\
	: "r" (I), "r" (&v->counter)					\
	: "memory");							\
}

ATOMIC_OP(add, add,  i)
ATOMIC_OP(sub, add, -i)
ATOMIC_OP(and, and,  i)
ATOMIC_OP( or,  or,  i)
ATOMIC_OP(xor, xor,  i)

#undef ATOMIC_OP

#define ATOMIC_FETCH_OP(op, asm_op, I)					\
static __always_inline							\
int arch_atomic_fetch_##op##_relaxed(int i, atomic_t *v)		\
{									\
	register int ret, tmp;						\
	__asm__ __volatile__ (						\
	"1:	ldex.w		%0, (%3) \n"				\
	"	mov		%1, %0   \n"				\
	"	" #op "		%0, %2   \n"				\
	"	stex.w		%0, (%3) \n"				\
	"	bez		%0, 1b   \n"				\
		: "=&r" (tmp), "=&r" (ret)				\
		: "r" (I), "r"(&v->counter) 				\
		: "memory");						\
	return ret;							\
}									\
static __always_inline							\
int arch_atomic_fetch_##op##_acquire(int i, atomic_t *v)		\
{									\
	register int ret, tmp;						\
	__asm__ __volatile__ (						\
	"1:	ldex.w		%0, (%3) \n"				\
	ACQUIRE_FENCE							\
	"	mov		%1, %0   \n"				\
	"	" #op "		%0, %2   \n"				\
	"	stex.w		%0, (%3) \n"				\
	"	bez		%0, 1b   \n"				\
		: "=&r" (tmp), "=&r" (ret)				\
		: "r" (I), "r"(&v->counter) 				\
		: "memory");						\
	return ret;							\
}									\
static __always_inline							\
int arch_atomic_fetch_##op##_release(int i, atomic_t *v)		\
{									\
	register int ret, tmp;						\
	__asm__ __volatile__ (						\
	"1:	ldex.w		%0, (%3) \n"				\
	"	mov		%1, %0   \n"				\
	"	" #op "		%0, %2   \n"				\
	RELEASE_FENCE							\
	"	stex.w		%0, (%3) \n"				\
	"	bez		%0, 1b   \n"				\
		: "=&r" (tmp), "=&r" (ret)				\
		: "r" (I), "r"(&v->counter) 				\
		: "memory");						\
	return ret;							\
}									\
static __always_inline							\
int arch_atomic_fetch_##op(int i, atomic_t *v)				\
{									\
	register int ret, tmp;						\
	__asm__ __volatile__ (						\
	"1:	ldex.w		%0, (%3) \n"				\
	ACQUIRE_FENCE							\
	"	mov		%1, %0   \n"				\
	"	" #op "		%0, %2   \n"				\
	RELEASE_FENCE							\
	"	stex.w		%0, (%3) \n"				\
	"	bez		%0, 1b   \n"				\
		: "=&r" (tmp), "=&r" (ret)				\
		: "r" (I), "r"(&v->counter) 				\
		: "memory");						\
	return ret;							\
}

#define ATOMIC_OP_RETURN(op, asm_op, c_op, I)				\
static __always_inline							\
int arch_atomic_##op##_return_relaxed(int i, atomic_t *v)		\
{									\
        return arch_atomic_fetch_##op##_relaxed(i, v) c_op I;		\
}									\
static __always_inline							\
int arch_atomic_##op##_return_acquire(int i, atomic_t *v)		\
{									\
        return arch_atomic_fetch_##op##_relaxed(i, v) c_op I;		\
}									\
static __always_inline							\
int arch_atomic_##op##_return_release(int i, atomic_t *v)		\
{									\
        return arch_atomic_fetch_##op##_release(i, v) c_op I;		\
}									\
static __always_inline							\
int arch_atomic_##op##_return(int i, atomic_t *v)			\
{									\
        return arch_atomic_fetch_##op(i, v) c_op I;			\
}

#define ATOMIC_OPS(op, asm_op, c_op, I)					\
        ATOMIC_FETCH_OP( op, asm_op,       I)				\
        ATOMIC_OP_RETURN(op, asm_op, c_op, I)

ATOMIC_OPS(add, add, +,  i)
ATOMIC_OPS(sub, add, +, -i)

#define arch_atomic_fetch_add_relaxed	arch_atomic_fetch_add_relaxed
#define arch_atomic_fetch_sub_relaxed	arch_atomic_fetch_sub_relaxed
#define arch_atomic_fetch_add_acquire	arch_atomic_fetch_add_acquire
#define arch_atomic_fetch_sub_acquire	arch_atomic_fetch_sub_acquire
#define arch_atomic_fetch_add_release	arch_atomic_fetch_add_release
#define arch_atomic_fetch_sub_release	arch_atomic_fetch_sub_release
#define arch_atomic_fetch_add		arch_atomic_fetch_add
#define arch_atomic_fetch_sub		arch_atomic_fetch_sub

#define arch_atomic_add_return_relaxed	arch_atomic_add_return_relaxed
#define arch_atomic_sub_return_relaxed	arch_atomic_sub_return_relaxed
#define arch_atomic_add_return_acquire	arch_atomic_add_return_acquire
#define arch_atomic_sub_return_acquire	arch_atomic_sub_return_acquire
#define arch_atomic_add_return_release	arch_atomic_add_return_release
#define arch_atomic_sub_return_release	arch_atomic_sub_return_release
#define arch_atomic_add_return		arch_atomic_add_return
#define arch_atomic_sub_return		arch_atomic_sub_return

#undef ATOMIC_OPS
#undef ATOMIC_OP_RETURN

#define ATOMIC_OPS(op, asm_op, I)					\
        ATOMIC_FETCH_OP(op, asm_op, I)

ATOMIC_OPS(and, and, i)
ATOMIC_OPS( or,  or, i)
ATOMIC_OPS(xor, xor, i)

#define arch_atomic_fetch_and_relaxed	arch_atomic_fetch_and_relaxed
#define arch_atomic_fetch_or_relaxed	arch_atomic_fetch_or_relaxed
#define arch_atomic_fetch_xor_relaxed	arch_atomic_fetch_xor_relaxed
#define arch_atomic_fetch_and_acquire	arch_atomic_fetch_and_acquire
#define arch_atomic_fetch_or_acquire	arch_atomic_fetch_or_acquire
#define arch_atomic_fetch_xor_acquire	arch_atomic_fetch_xor_acquire
#define arch_atomic_fetch_and_release	arch_atomic_fetch_and_release
#define arch_atomic_fetch_or_release	arch_atomic_fetch_or_release
#define arch_atomic_fetch_xor_release	arch_atomic_fetch_xor_release
#define arch_atomic_fetch_and		arch_atomic_fetch_and
#define arch_atomic_fetch_or		arch_atomic_fetch_or
#define arch_atomic_fetch_xor		arch_atomic_fetch_xor

#undef ATOMIC_OPS

#undef ATOMIC_FETCH_OP

#define ATOMIC_OP(size)							\
static __always_inline							\
int arch_atomic_xchg_relaxed(atomic_t *v, int n)			\
{									\
	return __xchg_relaxed(n, &(v->counter), size);			\
}									\
static __always_inline							\
int arch_atomic_xchg_acquire(atomic_t *v, int n)			\
{									\
	return __xchg_acquire(n, &(v->counter), size);			\
}									\
static __always_inline							\
int arch_atomic_xchg_release(atomic_t *v, int n)			\
{									\
	return __xchg_release(n, &(v->counter), size);			\
}									\
static __always_inline							\
int arch_atomic_xchg(atomic_t *v, int n)				\
{									\
	return __xchg(n, &(v->counter), size);				\
}									\
static __always_inline							\
int arch_atomic_cmpxchg_relaxed(atomic_t *v, int o, int n)		\
{									\
	return __cmpxchg_relaxed(&(v->counter), o, n, size);		\
}									\
static __always_inline							\
int arch_atomic_cmpxchg_acquire(atomic_t *v, int o, int n)		\
{									\
	return __cmpxchg_acquire(&(v->counter), o, n, size);		\
}									\
static __always_inline							\
int arch_atomic_cmpxchg_release(atomic_t *v, int o, int n)		\
{									\
	return __cmpxchg_release(&(v->counter), o, n, size);		\
}									\
static __always_inline							\
int arch_atomic_cmpxchg(atomic_t *v, int o, int n)			\
{									\
	return __cmpxchg(&(v->counter), o, n, size);			\
}

#define ATOMIC_OPS()							\
	ATOMIC_OP(4)

ATOMIC_OPS()

#define arch_atomic_xchg_relaxed	arch_atomic_xchg_relaxed
#define arch_atomic_xchg_acquire	arch_atomic_xchg_acquire
#define arch_atomic_xchg_release	arch_atomic_xchg_release
#define arch_atomic_xchg		arch_atomic_xchg
#define arch_atomic_cmpxchg_relaxed	arch_atomic_cmpxchg_relaxed
#define arch_atomic_cmpxchg_acquire	arch_atomic_cmpxchg_acquire
#define arch_atomic_cmpxchg_release	arch_atomic_cmpxchg_release
#define arch_atomic_cmpxchg		arch_atomic_cmpxchg

#undef ATOMIC_OPS
#undef ATOMIC_OP

#else
# include <asm-generic/atomic.h>
#endif

#endif /* __ASM_CSKY_ATOMIC_H */
