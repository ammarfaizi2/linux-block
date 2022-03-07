/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_COMPILER_H
#define LINUX_COMPILER_H

#define WRITE_ONCE(var, val) \
	(*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

#define __aligned(x) __attribute((__aligned__(x)))

#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

#endif
