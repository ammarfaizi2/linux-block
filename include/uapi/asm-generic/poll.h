#ifndef __ASM_GENERIC_POLL_H
#define __ASM_GENERIC_POLL_H

#ifdef __CHECK_POLL__
#define __POLL(x)	((__force __poll_t)(x))
#else
#define __POLL(x)	x
#endif

/* These are specified by iBCS2 */
#define POLLIN		__POLL(0x0001)
#define POLLPRI		__POLL(0x0002)
#define POLLOUT		__POLL(0x0004)
#define POLLERR		__POLL(0x0008)
#define POLLHUP		__POLL(0x0010)
#define POLLNVAL	__POLL(0x0020)

/* The rest seem to be more-or-less nonstandard. Check them! */
#define POLLRDNORM	__POLL(0x0040)
#define POLLRDBAND	__POLL(0x0080)
#ifndef POLLWRNORM
#define POLLWRNORM	__POLL(0x0100)
#endif
#ifndef POLLWRBAND
#define POLLWRBAND	__POLL(0x0200)
#endif
#ifndef POLLMSG
#define POLLMSG		__POLL(0x0400)
#endif
#ifndef POLLREMOVE
#define POLLREMOVE	__POLL(0x1000)
#endif
#ifndef POLLRDHUP
#define POLLRDHUP       __POLL(0x2000)
#endif

#define POLLFREE	__POLL(0x4000)	/* currently only for epoll */

#define POLL_BUSY_LOOP	__POLL(0x8000)

struct pollfd {
	int fd;
	short events;
	short revents;
};

#endif	/* __ASM_GENERIC_POLL_H */
