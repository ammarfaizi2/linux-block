/*
 * include/asm-xtensa/poll.h
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2001 - 2005 Tensilica Inc.
 */

#ifndef _XTENSA_POLL_H
#define _XTENSA_POLL_H

#define POLLWRNORM	POLLOUT
#define POLLWRBAND	__POLL(0x0100)
#define POLLREMOVE	__POLL(0x0800)

#include <asm-generic/poll.h>

#endif /* _XTENSA_POLL_H */
