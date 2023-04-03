// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TCP sink server
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
	fprintf(stderr, "tcp-sink [-4][-p<port>]\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	unsigned int port = 5555;
	bool ipv6 = true;
	int opt, server_sock, sock;


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
		server_sock = socket(AF_INET, SOCK_STREAM, 0);
		OSERROR(server_sock, "socket");
		OSERROR(bind(server_sock, (struct sockaddr *)&sin, sizeof(sin)), "bind");
		OSERROR(listen(server_sock, 1), "listen");
	} else {
		struct sockaddr_in6 sin6 = {
			.sin6_family = AF_INET6,
			.sin6_port   = htons(port),
		};
		server_sock = socket(AF_INET6, SOCK_STREAM, 0);
		OSERROR(server_sock, "socket");
		OSERROR(bind(server_sock, (struct sockaddr *)&sin6, sizeof(sin6)), "bind");
		OSERROR(listen(server_sock, 1), "listen");
	}

	for (;;) {
		sock = accept(server_sock, NULL, NULL);
		if (sock != -1) {
			while (read(sock, buffer, sizeof(buffer)) > 0) {}
			close(sock);
		}
	}
}
