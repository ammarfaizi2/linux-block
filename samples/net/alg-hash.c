// SPDX-License-Identifier: GPL-2.0-or-later
/* AF_ALG hash test
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
#include <linux/if_alg.h>

#define OSERROR(X, Y) do { if ((long)(X) == -1) { perror(Y); exit(1); } } while(0)

static unsigned char buffer[4096 * 32] __attribute__((aligned(4096)));

static const struct sockaddr_alg sa = {
	.salg_family	= AF_ALG,
	.salg_type	= "hash",
	.salg_name	= "sha1",
};

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr, "alg-send [-s] [-n<size>] <file>|-\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	struct stat st;
	const char *filename;
	ssize_t r, w, o, ret;
	size_t size = LONG_MAX, i;
	char *end;
	int use_sendfile = 0;
	int opt, alg, sock, fd = 0;

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
	if (argc != 1)
		format();
	filename = argv[0];

	alg = socket(AF_ALG, SOCK_SEQPACKET, 0);
	OSERROR(alg, "AF_ALG");
	OSERROR(bind(alg, (struct sockaddr *)&sa, sizeof(sa)), "bind");
	sock = accept(alg, NULL, 0);
	OSERROR(sock, "accept");

	if (strcmp(filename, "-") != 0) {
		fd = open(filename, O_RDONLY);
		OSERROR(fd, filename);
		OSERROR(fstat(fd, &st), filename);
		size = st.st_size;
	} else {
		OSERROR(fstat(fd, &st), argv[2]);
	}

	if (!use_sendfile) {
		bool more = false;

		while (size) {
			r = read(fd, buffer, sizeof(buffer));
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
			} while (o < r);
		}

		if (more)
			send(sock, NULL, 0, 0);
	} else if (S_ISFIFO(st.st_mode)) {
		r = splice(fd, NULL, sock, NULL, size, 0);
		OSERROR(r, "sock/splice");
		if (r != size) {
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
	}

	ret = read(sock, buffer, sizeof(buffer));
	OSERROR(ret, "sock/read");

	for (i = 0; i < ret; i++)
		printf("%02x", (unsigned char)buffer[i]);
	printf("\n");

	OSERROR(close(sock), "sock/close");
	OSERROR(close(alg), "alg/close");
	OSERROR(close(fd), "close");
	return 0;
}
