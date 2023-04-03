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
#define min(x, y) ((x) < (y) ? (x) : (y))

static unsigned char buffer[4096 * 32] __attribute__((aligned(4096)));
static unsigned char iv[16];
static unsigned char key[16];

static const struct sockaddr_alg sa = {
	.salg_family	= AF_ALG,
	.salg_type	= "skcipher",
	.salg_name	= "cbc(aes)",
};

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr, "alg-send [-s] [-n<size>] <file>|-\n");
	exit(2);
}

static void algif_add_set_op(struct msghdr *msg, unsigned int op)
{
	struct cmsghdr *__cmsg;

	__cmsg = msg->msg_control + msg->msg_controllen;
	__cmsg->cmsg_len	= CMSG_LEN(sizeof(unsigned int));
	__cmsg->cmsg_level	= SOL_ALG;
	__cmsg->cmsg_type	= ALG_SET_OP;
	*(unsigned int *)CMSG_DATA(__cmsg) = op;
	msg->msg_controllen += CMSG_ALIGN(__cmsg->cmsg_len);
}

static void algif_add_set_iv(struct msghdr *msg, const void *iv, size_t ivlen)
{
	struct af_alg_iv *ivbuf;
	struct cmsghdr *__cmsg;

	printf("%zx\n", msg->msg_controllen);
	__cmsg = msg->msg_control + msg->msg_controllen;
	__cmsg->cmsg_len	= CMSG_LEN(sizeof(*ivbuf) + ivlen);
	__cmsg->cmsg_level	= SOL_ALG;
	__cmsg->cmsg_type	= ALG_SET_IV;
	ivbuf = (struct af_alg_iv *)CMSG_DATA(__cmsg);
	ivbuf->ivlen = ivlen;
	memcpy(ivbuf->iv, iv, ivlen);
	msg->msg_controllen += CMSG_ALIGN(__cmsg->cmsg_len);
}

int main(int argc, char *argv[])
{
	struct msghdr msg;
	struct stat st;
	const char *filename;
	unsigned char ctrl[4096];
	ssize_t r, w, o, ret;
	size_t size = LONG_MAX, total = 0, i, out = 160;
	char *end;
	bool use_sendfile = false, all = true;
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
	if (argc != 1)
		format();
	filename = argv[0];

	alg = socket(AF_ALG, SOCK_SEQPACKET, 0);
	OSERROR(alg, "AF_ALG");
	OSERROR(bind(alg, (struct sockaddr *)&sa, sizeof(sa)), "bind");
	OSERROR(setsockopt(alg, SOL_ALG, ALG_SET_KEY, key, sizeof(key)), "ALG_SET_KEY");
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

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = ctrl;
	algif_add_set_op(&msg, ALG_OP_ENCRYPT);
	algif_add_set_iv(&msg, iv, sizeof(iv));

	OSERROR(sendmsg(sock, &msg, MSG_MORE), "sock/sendmsg");

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
				total += w;
				o += w;
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
		total = r;
	}

	while (total > 0) {
		ret = read(sock, buffer, min(sizeof(buffer), total));
		OSERROR(ret, "sock/read");
		if (ret == 0)
			break;
		total -= ret;

		if (out > 0) {
			ret = min(out, ret);
			out -= ret;
			for (i = 0; i < ret; i++)
				printf("%02x", (unsigned char)buffer[i]);
		}
		printf("...\n");
	}

	OSERROR(close(sock), "sock/close");
	OSERROR(close(alg), "alg/close");
	OSERROR(close(fd), "close");
	return 0;
}
