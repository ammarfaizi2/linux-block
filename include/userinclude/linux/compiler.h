/*
 * When uapi headers are installed, #include <linux/compiler.h> is stripped.
 *
 * When uapi headers are used when building normal kernel code,
 * #include <linux/compiler.h> finds the normal linux/compiler.h
 *
 * When uapi headers are included in-tree using USERINCLUDE,
 * linux/compiler.h resolves to this file.
 */

/*#include "../../linux/compiler.h"*/
