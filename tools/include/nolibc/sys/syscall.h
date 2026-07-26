/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * syscall() definition for NOLIBC
 * Copyright (C) 2024 Thomas Weißschuh <linux@weissschuh.net>
 */

/* make sure to include all global symbols */
#include "../nolibc.h"

#ifndef _NOLIBC_SYS_SYSCALL_H
#define _NOLIBC_SYS_SYSCALL_H

/*
 * The __nolibc_syscallN() macros assign their arguments to local register
 * variables. A compiler only has to keep such a variable in its register
 * right before the asm statement it feeds, so an argument expression which
 * contains a function call gets evaluated once the earlier arguments already
 * sit in their registers, and the call then clobbers them.
 *
 * Caller-supplied expressions enter here, so bind them to temporaries first
 * and only hand plain variables over. __auto_type preserves the original
 * type, so nothing gets truncated on the way.
 */
#define __nolibc_syscall_eval0(_n)					\
({									\
	__auto_type __sc_n = (_n);					\
	__nolibc_syscall0(__sc_n);					\
})
#define __nolibc_syscall_eval1(_n, _a1)					\
({									\
	__auto_type __sc_n = (_n);					\
	__auto_type __sc_a1 = (_a1);					\
	__nolibc_syscall1(__sc_n, __sc_a1);				\
})
#define __nolibc_syscall_eval2(_n, _a1, _a2)				\
({									\
	__auto_type __sc_n = (_n);					\
	__auto_type __sc_a1 = (_a1);					\
	__auto_type __sc_a2 = (_a2);					\
	__nolibc_syscall2(__sc_n, __sc_a1, __sc_a2);			\
})
#define __nolibc_syscall_eval3(_n, _a1, _a2, _a3)			\
({									\
	__auto_type __sc_n = (_n);					\
	__auto_type __sc_a1 = (_a1);					\
	__auto_type __sc_a2 = (_a2);					\
	__auto_type __sc_a3 = (_a3);					\
	__nolibc_syscall3(__sc_n, __sc_a1, __sc_a2, __sc_a3);		\
})
#define __nolibc_syscall_eval4(_n, _a1, _a2, _a3, _a4)			\
({									\
	__auto_type __sc_n = (_n);					\
	__auto_type __sc_a1 = (_a1);					\
	__auto_type __sc_a2 = (_a2);					\
	__auto_type __sc_a3 = (_a3);					\
	__auto_type __sc_a4 = (_a4);					\
	__nolibc_syscall4(__sc_n, __sc_a1, __sc_a2, __sc_a3, __sc_a4);	\
})
#define __nolibc_syscall_eval5(_n, _a1, _a2, _a3, _a4, _a5)		\
({									\
	__auto_type __sc_n = (_n);					\
	__auto_type __sc_a1 = (_a1);					\
	__auto_type __sc_a2 = (_a2);					\
	__auto_type __sc_a3 = (_a3);					\
	__auto_type __sc_a4 = (_a4);					\
	__auto_type __sc_a5 = (_a5);					\
	__nolibc_syscall5(__sc_n, __sc_a1, __sc_a2, __sc_a3, __sc_a4,	\
			  __sc_a5);					\
})
#define __nolibc_syscall_eval6(_n, _a1, _a2, _a3, _a4, _a5, _a6)	\
({									\
	__auto_type __sc_n = (_n);					\
	__auto_type __sc_a1 = (_a1);					\
	__auto_type __sc_a2 = (_a2);					\
	__auto_type __sc_a3 = (_a3);					\
	__auto_type __sc_a4 = (_a4);					\
	__auto_type __sc_a5 = (_a5);					\
	__auto_type __sc_a6 = (_a6);					\
	__nolibc_syscall6(__sc_n, __sc_a1, __sc_a2, __sc_a3, __sc_a4,	\
			  __sc_a5, __sc_a6);				\
})

#define ___nolibc_syscall_narg(_0, _1, _2, _3, _4, _5, _6, N, ...) N
#define __nolibc_syscall_narg(...) ___nolibc_syscall_narg(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define __nolibc_syscall(N, ...) __nolibc_syscall_eval##N(__VA_ARGS__)
#define __nolibc_syscall_n(N, ...) __nolibc_syscall(N, __VA_ARGS__)
#define _syscall(...) __nolibc_syscall_n(__nolibc_syscall_narg(__VA_ARGS__), ##__VA_ARGS__)
#define syscall(...) __sysret(_syscall(__VA_ARGS__))

#endif /* _NOLIBC_SYS_SYSCALL_H */
