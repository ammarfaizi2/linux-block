#ifndef __SPARC_POLL_H
#define __SPARC_POLL_H

#define POLLWRNORM	POLLOUT
#define POLLWRBAND	__POLL(256)
#define POLLMSG		__POLL(512)
#define POLLREMOVE	__POLL(1024)
#define POLLRDHUP       __POLL(2048)

#include <asm-generic/poll.h>

#endif
