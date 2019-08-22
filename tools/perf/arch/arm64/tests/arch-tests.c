// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "tests/tests.h"
#include "arch-tests.h"

struct test arch_tests[] = {
#ifdef HAVE_DWARF_UNWIND_SUPPORT
	{
		.desc = "DWARF unwind",
		.func = test__dwarf_unwind,
	},
#endif
	{
		.desc = "User event counter access",
		.func = test__rd_pmevcntr,
	},
	{
		.desc = "User cycle counter access",
		.func = test__rd_pmccntr,
	},
	{
		.desc = "Pinned CPU user counter access",
		.func = test__rd_pinned,
	},
	{
		.func = NULL,
	},
};
