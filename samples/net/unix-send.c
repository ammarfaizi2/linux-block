// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AF_UNIX stream send client.  Pass -s to use splice/sendfile.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#define OSERROR(X, Y) do { if ((long)(X) == -1) { perror(Y); exit(1); } } while(0)
#define min(x, y) ((x) < (y) ? (x) : (y))

static unsigned char buffer[4096] __attribute__((aligned(4096)));

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr, "unix-send [-s] [-n<size>] <file>|- <socket-file>\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX, };
	struct stat st;
	const char *filename, *sockname;
	ssize_t r, w, o, size = LONG_MAX;
	size_t plen, total = 0;
	char *end;
	bool use_sendfile = false, all = true;
	int opt, sock, fd = 0;

	while ((opt = getopt(argc, argv, "n:s")) != EOF) {
		switch (opt) {
		case 'n':
			size = strtoul(optarg, &end, 0);
			switch (*end) {
			case 'K':
			case 'k':
				size *= 1024;
				break;
			case 'M':
			case 'm':
				size *= 1024 * 1024;
				break;
			}
			all = false;
			break;
		case 's':
			use_sendfile = true;
			break;
		default:
			format();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 2)
		format();
	filename = argv[0];
	sockname = argv[1];

	plen = strlen(sockname);
	if (plen == 0 || plen > sizeof(sun.sun_path) - 1) {
		fprintf(stderr, "socket filename too short or too long\n");
		exit(2);
	}
	memcpy(sun.sun_path, sockname, plen + 1);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	OSERROR(sock, "socket");
	OSERROR(connect(sock, (struct sockaddr *)&sun, sizeof(sun)), "connect");

	if (strcmp(filename, "-") != 0) {
		fd = open(filename, O_RDONLY);
		OSERROR(fd, filename);
		OSERROR(fstat(fd, &st), filename);
		if (size > st.st_size)
			size = st.st_size;
	} else {
		OSERROR(fstat(fd, &st), argv[2]);
	}

	if (!use_sendfile) {
		bool more = false;

		while (size) {
			r = read(fd, buffer, min(sizeof(buffer), size));
			OSERROR(r, filename);
			if (r == 0)
				break;
			size -= r;

			o = 0;
			do {
				more = size > 0;
				w = send(sock, buffer + o, r - o,
					 more ? MSG_MORE : 0);
				OSERROR(w, "sock/send");
				o += w;
				total += w;
			} while (o < r);
		}

		if (more)
			send(sock, NULL, 0, 0);
	} else if (S_ISFIFO(st.st_mode)) {
		do {
			r = splice(fd, NULL, sock, NULL, size,
				   size > 0 ? SPLICE_F_MORE : 0);
			OSERROR(r, "sock/splice");
			size -= r;
			total += r;
		} while (r > 0 && size > 0);
		if (size && !all) {
			fprintf(stderr, "Short splice\n");
			exit(1);
		}
	} else {
		r = sendfile(sock, fd, NULL, size);
		OSERROR(r, "sock/sendfile");
		if (r != size) {
			fprintf(stderr, "Short sendfile\n");
			exit(1);
		}
		total += r;
	}

	printf("Sent %zu bytes\n", total);
	OSERROR(close(sock), "sock/close");
	OSERROR(close(fd), "close");
	return 0;
}
