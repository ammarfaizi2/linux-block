/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SOCKET_TYPES_H
#define _LINUX_SOCKET_TYPES_H

#include <uapi/linux/socket.h>
#include <uapi/linux/socket_types.h>

/*
 *	1003.1g requires sa_family_t and that sa_data is char.
 */

struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};

struct linger {
	int		l_onoff;	/* Linger active		*/
	int		l_linger;	/* How long to linger for	*/
};

#endif /* _LINUX_SOCKET_TYPES_H */
