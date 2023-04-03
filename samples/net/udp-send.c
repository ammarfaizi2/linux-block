// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * UDP send client.  Pass -s to splice.
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
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#define OSERROR(X, Y) do { if ((long)(X) == -1) { perror(Y); exit(1); } } while(0)
#define min(x, y) ((x) < (y) ? (x) : (y))

static unsigned char buffer[65536] __attribute__((aligned(4096)));

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr, "udp-send [-46s][-n<size>][-p<port>] <file>|- <server>\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	struct addrinfo *addrs = NULL, hints = {};
	struct stat st;
	const char *filename, *sockname, *service = "5555";
	unsigned int len;
	ssize_t r, o, size = 65535;
	char *end;
	bool use_sendfile = false;
	int opt, sock, fd = 0, gai;

	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	while ((opt = getopt(argc, argv, "46n:p:s")) != EOF) {
		switch (opt) {
		case '4':
			hints.ai_family = AF_INET;
			break;
		case '6':
			hints.ai_family = AF_INET6;
			break;
		case 'n':
			size = strtoul(optarg, &end, 0);
			switch (*end) {
			case 'K':
			case 'k':
				size *= 1024;
				break;
			}
			if (size > 65535) {
				fprintf(stderr, "Too much data for UDP packet\n");
				exit(2);
			}
			break;
		case 'p':
			service = optarg;
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

	gai = getaddrinfo(sockname, service, &hints, &addrs);
	if (gai) {
		fprintf(stderr, "%s: %s\n", sockname, gai_strerror(gai));
		exit(3);
	}

	if (!addrs) {
		fprintf(stderr, "%s: No addresses\n", sockname);
		exit(3);
	}

	sockname = addrs->ai_canonname;
	sock = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
	OSERROR(sock, "socket");
	OSERROR(connect(sock, addrs->ai_addr, addrs->ai_addrlen), "connect");

	if (strcmp(filename, "-") != 0) {
		fd = open(filename, O_RDONLY);
		OSERROR(fd, filename);
		OSERROR(fstat(fd, &st), filename);
		if (size > st.st_size)
			size = st.st_size;
	} else {
		OSERROR(fstat(fd, &st), filename);
	}

	len = htonl(size);
	OSERROR(send(sock, &len, 4, MSG_MORE), "sock/send");

	if (!use_sendfile) {
		while (size) {
			r = read(fd, buffer, sizeof(buffer));
			OSERROR(r, filename);
			if (r == 0)
				break;
			size -= r;

			o = 0;
			do {
				ssize_t w = send(sock, buffer + o, r - o,
						 size > 0 ? MSG_MORE : 0);
				OSERROR(w, "sock/send");
				o += w;
			} while (o < r);
		}
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

	OSERROR(close(sock), "sock/close");
	OSERROR(close(fd), "close");
	return 0;
}
