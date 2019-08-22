/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_TESTS_H
#define ARCH_TESTS_H

#include <linux/compiler.h>

#ifdef HAVE_DWARF_UNWIND_SUPPORT
struct thread;
struct perf_sample;
int test__arch_unwind_sample(struct perf_sample *sample,
			     struct thread *thread);
#endif

extern struct test arch_tests[];
int test__rd_pinned(struct test __maybe_unused *test,
		       int __maybe_unused subtest);


#endif
