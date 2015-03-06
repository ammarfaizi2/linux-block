#ifndef _ASM_POLL_H
#define _ASM_POLL_H

#define POLLWRNORM	POLLOUT
#define POLLWRBAND	__POLL(256)

#include <asm-generic/poll.h>

#undef POLLREMOVE

#endif

