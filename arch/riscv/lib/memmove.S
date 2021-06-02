/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/asm.h>

ENTRY(__memmove)
	tail memmove
END(__memmove)
