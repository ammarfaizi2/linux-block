// SPDX-License-Identifier: GPL-2.0
/* Intercept request_key upcalls
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <keyutils.h>
#include <linux/watch_queue.h>
#include <linux/unistd.h>

#ifndef KEYCTL_WATCH_KEY
#define KEYCTL_WATCH_KEY 32
#endif
#ifndef KEYCTL_SERVICE_INTERCEPT
#define KEYCTL_SERVICE_INTERCEPT 33
#endif
#ifndef __NR_keyctl
#define __NR_keyctl -1
#endif

#define BUF_SIZE 256

typedef int key_serial_t;
key_serial_t queue_keyring;

static long keyctl_watch_key(int key, int watch_fd, int watch_id)
{
	return syscall(__NR_keyctl, KEYCTL_WATCH_KEY, key, watch_fd, watch_id);
}

static long keyctl_service_intercept(int queue_keyring, int userns_fd,
				     const char *type_name, unsigned int ns_mask)
{
	return syscall(__NR_keyctl, KEYCTL_SERVICE_INTERCEPT,
		       queue_keyring, userns_fd, type_name, ns_mask);
}

static const char auth_key_type[] = ".request_key_auth;";

/*
 * Instantiate a key.
 */
static void do_instantiation(key_serial_t key, char *desc)
{
	printf("INSTANTIATE %u '%s'\n", key, desc);

	if (keyctl_assume_authority(key) == -1) {
		perror("keyctl_assume_authority");
		exit(1);
	}

	if (keyctl_reject(key, 20, ENOANO, 0) == -1) {
		perror("keyctl_reject");
		exit(1);
	}
}

/*
 * Process a notification.
 */
static void process_request(struct watch_notification *n, size_t len)
{
	struct key_notification *k = (struct key_notification *)n;
	key_serial_t auth_key, key;
	char desc[1024], *p;

	if (len != sizeof(struct key_notification)) {
		fprintf(stderr, "Incorrect key message length\n");
		return;
	}

	auth_key = k->aux;
	printf("REQUEST %d aux=%d\n", k->key_id, k->aux);

	if (keyctl_describe(auth_key, desc, sizeof(desc)) == -1) {
		perror("keyctl_describe(auth_key)");
		exit(1);
	}

	printf("AUTH_KEY '%s'\n", desc);
	if (memcmp(desc, auth_key_type, sizeof(auth_key_type) - 1) != 0) {
		printf("NOT AUTH_KEY TYPE\n");
	} else {
		p = strrchr(desc, ';');
		if (p) {
			key = strtoul(p + 1, NULL, 16);
			printf("KEY '%d'\n", key);

			if (keyctl_describe(key, desc, sizeof(desc)) == -1) {
				perror("keyctl_describe(key)");
				exit(1);
			}

			do_instantiation(key, desc);
			return;
		}
	}

	/* Shouldn't need to do this if we successfully instantiated/rejected
	 * the target key.
	 */
	if (keyctl_unlink(auth_key, queue_keyring) == -1)
		perror("keyctl_unlink");
}

/*
 * Consume and display events.
 */
static void consumer(int fd)
{
	unsigned char buffer[433], *p, *end;
	union {
		struct watch_notification n;
		unsigned char buf1[128];
	} n;
	ssize_t buf_len;

	for (;;) {
		buf_len = read(fd, buffer, sizeof(buffer));
		if (buf_len == -1) {
			perror("read");
			exit(1);
		}

		if (buf_len == 0) {
			printf("-- END --\n");
			return;
		}

		if (buf_len > sizeof(buffer)) {
			fprintf(stderr, "Read buffer overrun: %zd\n", buf_len);
			return;
		}

		printf("read() = %zd\n", buf_len);

		p = buffer;
		end = buffer + buf_len;
		while (p < end) {
			size_t largest, len;

			largest = end - p;
			if (largest > 128)
				largest = 128;
			if (largest < sizeof(struct watch_notification)) {
				fprintf(stderr, "Short message header: %zu\n", largest);
				return;
			}
			memcpy(&n, p, largest);

			printf("NOTIFY[%03zx]: ty=%06x sy=%02x i=%08x\n",
			       p - buffer, n.n.type, n.n.subtype, n.n.info);

			len = n.n.info & WATCH_INFO_LENGTH;
			if (len < sizeof(n.n) || len > largest) {
				fprintf(stderr, "Bad message length: %zu/%zu\n", len, largest);
				exit(1);
			}

			switch (n.n.type) {
			case WATCH_TYPE_META:
				switch (n.n.subtype) {
				case WATCH_META_REMOVAL_NOTIFICATION:
					printf("REMOVAL of watchpoint %08x\n",
					       (n.n.info & WATCH_INFO_ID) >>
					       WATCH_INFO_ID__SHIFT);
					break;
				case WATCH_META_LOSS_NOTIFICATION:
					printf("-- LOSS --\n");
					break;
				default:
					printf("other meta record\n");
					break;
				}
				break;
			case WATCH_TYPE_KEY_NOTIFY:
				switch (n.n.subtype) {
				case NOTIFY_KEY_LINKED:
					process_request(&n.n, len);
					break;
				default:
					printf("other key subtype\n");
					break;
				}
				break;
			default:
				printf("other type\n");
				break;
			}

			p += len;
		}
	}
}

static struct watch_notification_filter filter = {
	.nr_filters	= 1,
	.filters = {
		[0]	= {
			.type			= WATCH_TYPE_KEY_NOTIFY,
			.subtype_filter[0]	= (1 << NOTIFY_KEY_LINKED),
		},
	},
};

static void cleanup(void)
{
	printf("--- clean up ---\n");
	if (keyctl_service_intercept(0, -1, "user", 0) == -1)
		perror("unintercept");
	if (keyctl_clear(queue_keyring) == -1)
		perror("clear");
	if (keyctl_unlink(queue_keyring, KEY_SPEC_SESSION_KEYRING) == -1)
		perror("unlink/q");
}

int main(int argc, char **argv)
{
	int pipefd[2], fd;

	queue_keyring = add_key("keyring", "intercept", NULL, 0, KEY_SPEC_SESSION_KEYRING);
	if (queue_keyring == -1) {
		perror("add_key");
		exit(1);
	}

	printf("QUEUE KEYRING %d\n", queue_keyring);

	if (pipe2(pipefd, O_NOTIFICATION_PIPE) == -1) {
		perror("pipe2");
		exit(1);
	}
	fd = pipefd[0];

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_SIZE, BUF_SIZE) == -1) {
		perror("watch_queue(size)");
		exit(1);
	}

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_FILTER, &filter) == -1) {
		perror("watch_queue(filter)");
		exit(1);
	}

	if (keyctl_watch_key(queue_keyring, fd, 0x01) == -1) {
		perror("keyctl_watch_key");
		exit(1);
	}

	if (keyctl_service_intercept(queue_keyring, -1, "user", 0) == -1) {
		perror("keyctl_service_intercept");
		exit(1);
	}

	atexit(cleanup);

	consumer(fd);
	exit(0);
}
