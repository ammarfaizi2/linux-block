// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * UNIX stream sink server
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#define OSERROR(X, Y) do { if ((long)(X) == -1) { perror(Y); exit(1); } } while(0)

static unsigned char buffer[512 * 1024] __attribute__((aligned(4096)));

int main(int argc, char *argv[])
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX, };
	size_t plen;
	int server_sock, sock;

	if (argc != 2) {
		fprintf(stderr, "unix-sink <socket-file>\n");
		exit(2);
	}

	plen = strlen(argv[1]);
	if (plen == 0 || plen > sizeof(sun.sun_path) - 1) {
		fprintf(stderr, "socket filename too short or too long\n");
		exit(2);
	}
	memcpy(sun.sun_path, argv[1], plen + 1);

	server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	OSERROR(server_sock, "socket");
	OSERROR(bind(server_sock, (struct sockaddr *)&sun, sizeof(sun)), "bind");
	OSERROR(listen(server_sock, 1), "listen");

	for (;;) {
		sock = accept(server_sock, NULL, NULL);
		if (sock != -1) {
			while (read(sock, buffer, sizeof(buffer)) > 0) {}
			close(sock);
		}
	}
}
