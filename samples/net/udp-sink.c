// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * UDP sink server
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

#define OSERROR(X, Y) do { if ((long)(X) == -1) { perror(Y); exit(1); } } while(0)

static unsigned char buffer[512 * 1024] __attribute__((aligned(4096)));

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr, "udp-sink [-4][-p<port>]\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	struct iovec iov[1] = {
		[0] = {
			.iov_base	= buffer,
			.iov_len	= sizeof(buffer),
		},
	};
	struct msghdr msg = {
		.msg_iov	= iov,
		.msg_iovlen	= 1,
	};
	unsigned int port = 5555;
	bool ipv6 = true;
	int opt, sock;

	while ((opt = getopt(argc, argv, "4p:")) != EOF) {
		switch (opt) {
		case '4':
			ipv6 = false;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		default:
			format();
		}
	}

	if (!ipv6) {
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_port   = htons(port),
		};
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		OSERROR(sock, "socket");
		OSERROR(bind(sock, (struct sockaddr *)&sin, sizeof(sin)), "bind");
	} else {
		struct sockaddr_in6 sin6 = {
			.sin6_family = AF_INET6,
			.sin6_port   = htons(port),
		};
		sock = socket(AF_INET6, SOCK_DGRAM, 0);
		OSERROR(sock, "socket");
		OSERROR(bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)), "bind");
	}

	for (;;) {
		ssize_t r;

		r = recvmsg(sock, &msg, 0);
		printf("rx %zd\n", r);
	}
}
