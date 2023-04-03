// SPDX-License-Identifier: GPL-2.0-or-later
/* Splice or sendfile from the given file/stdin to stdout.
 *
 * Format: splice-out [-s] <file>|- [<size>]
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#define OSERROR(X, Y) do { if ((long)(X) == -1) { perror(Y); exit(1); } } while(0)
#define min(x, y) ((x) < (y) ? (x) : (y))

static unsigned char buffer[4096] __attribute__((aligned(4096)));

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr, "splice-out [-kN][-s][-wN] <file>|- [<size>]\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	const char *filename;
	struct stat st;
	ssize_t r;
	size_t size = 1024 * 1024, skip = 0, unit = 0, part;
	char *end;
	bool use_sendfile = false, all = true;
	int opt, fd = 0;

	while ((opt = getopt(argc, argv, "k:sw:")),
	       opt != -1) {
		switch (opt) {
		case 'k':
			/* Skip size - prevent coalescence. */
			skip = strtoul(optarg, &end, 0);
			if (skip < 1 || skip >= 4096) {
				fprintf(stderr, "-kN must be 0<N<4096\n");
				exit(2);
			}
			break;
		case 's':
			use_sendfile = 1;
			break;
		case 'w':
			/* Write unit size */
			unit = strtoul(optarg, &end, 0);
			if (!unit) {
				fprintf(stderr, "-wN must be >0\n");
				exit(2);
			}
			switch (*end) {
			case 'K':
			case 'k':
				unit *= 1024;
				break;
			case 'M':
			case 'm':
				unit *= 1024 * 1024;
				break;
			}
			break;
		default:
			format();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 && argc != 2)
		format();

	filename = argv[0];
	if (argc == 2) {
		size = strtoul(argv[1], &end, 0);
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
	}

	OSERROR(fstat(1, &st), "stdout");
	if (!S_ISFIFO(st.st_mode)) {
		fprintf(stderr, "stdout must be a pipe\n");
		exit(3);
	}

	if (strcmp(filename, "-") != 0) {
		fd = open(filename, O_RDONLY);
		OSERROR(fd, filename);
		OSERROR(fstat(fd, &st), filename);
		if (!all && size > st.st_size) {
			fprintf(stderr, "%s: Specified size larger than file\n", filename);
			exit(3);
		}
	}

	do {
		if (skip) {
			part = skip;
			do {
				r = read(fd, buffer, skip);
				OSERROR(r, filename);
				part -= r;
			} while (part > 0 && r > 0);
		}

		part = unit ? min(size, unit) : size;
		if (use_sendfile) {
			r = sendfile(1, fd, NULL, part);
			OSERROR(r, "sendfile");
		} else {
			r = splice(fd, NULL, 1, NULL, part, 0);
			OSERROR(r, "splice");
		}
		if (!all)
			size -= r;
	} while (r > 0 && size > 0);

	OSERROR(close(fd), "close");
	return 0;
}
