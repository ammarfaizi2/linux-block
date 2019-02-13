/* Container keyring upcall management test.
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <keyutils.h>
#include <linux/watch_queue.h>

#define KEYCTL_WATCH_KEY		30	/* Watch a key or ring of keys for changes */
#define KEYCTL_QUERY_REQUEST_KEY_AUTH	32	/* Query a request_key_auth key */
#define KEYCTL_MOVE			33	/* Move keys between keyrings */
#define KEYCTL_FIND_LRU			34	/* Find the least-recently used key in a keyring */

struct keyctl_query_request_key_auth {
	char		operation[32];	/* Operation name, typically "create" */
	uid_t		fsuid;		/* UID of requester */
	gid_t		fsgid;		/* GID of requester */
	key_serial_t	target_key;	/* The key being instantiated */
	key_serial_t	thread_keyring;	/* The requester's thread keyring */
	key_serial_t	process_keyring; /* The requester's process keyring */
	key_serial_t	session_keyring; /* The requester's session keyring */
	long long	spare[1];
};

static void process_request(key_serial_t keyring, key_serial_t key)
{
	struct keyctl_query_request_key_auth info;
	char target[32], uid[32], gid[32], thread[32], process[32], session[32];
	void *callout;
	long len;

#if 0
	key = keyctl(KEYCTL_FIND_LRU, keyring, ".request_key_auth");
	if (key == -1) {
		perror("keyctl/find");
		exit(1);
	}
#endif

	if (keyctl(KEYCTL_QUERY_REQUEST_KEY_AUTH, key, &info) == -1) {
		perror("keyctl/query");
		exit(1);
	}

	len = keyctl_read_alloc(key, &callout);
	if (len == -1) {
		perror("keyctl/read");
		exit(1);
	}

	sprintf(target, "%d", info.target_key);
	sprintf(uid, "%d", info.fsuid);
	sprintf(gid, "%d", info.fsgid);
	sprintf(thread, "%d", info.thread_keyring);
	sprintf(process, "%d", info.process_keyring);
	sprintf(session, "%d", info.session_keyring);

	printf("Authentication key %d\n", key);
	printf("- %s %s\n", info.operation, target);
	printf("- uid=%s gid=%s\n", uid, gid);
	printf("- rings=%s,%s,%s\n", thread, process, session);
	printf("- callout='%s'\n", (char *)callout);

	switch (fork()) {
	case 0:
		/* Only pass the auth token of interest onto /sbin/request-key */
		if (keyctl(KEYCTL_MOVE, key, keyring, KEY_SPEC_THREAD_KEYRING) < 0) {
			perror("keyctl_move/1");
			exit(1);
		}

		if (keyctl_join_session_keyring(NULL) < 0) {
			perror("keyctl_join");
			exit(1);
		}

		if (keyctl(KEYCTL_MOVE, key,
			   KEY_SPEC_THREAD_KEYRING, KEY_SPEC_SESSION_KEYRING) < 0) {
			perror("keyctl_move/2");
			exit(1);
		}

		execl("/sbin/request-key",
		      "request-key", info.operation, target, uid, gid, thread, process, session,
		      NULL);
		perror("execve");
		exit(1);

	case -1:
		perror("fork");
		exit(1);

	default:
		return;
	}
}

/*
 * We saw a change on the keyring.
 */
static void saw_key_change(struct watch_notification *n)
{
	struct key_notification *k = (struct key_notification *)n;
	unsigned int len = n->info & WATCH_INFO_LENGTH;

	if (len != sizeof(struct key_notification))
		return;

	printf("KEY %d change=%u aux=%d\n", k->key_id, n->subtype, k->aux);

	process_request(k->key_id, k->aux);
}

/*
 * Consume and display events.
 */
static int consumer(int fd, struct watch_queue_buffer *buf)
{
	struct watch_notification *n;
	struct pollfd p[1];
	unsigned int head, tail, mask = buf->meta.mask;

	for (;;) {
		p[0].fd = fd;
		p[0].events = POLLIN | POLLERR;
		p[0].revents = 0;

		if (poll(p, 1, -1) == -1) {
			perror("poll");
			break;
		}

		printf("ptrs h=%x t=%x m=%x\n",
		       buf->meta.head, buf->meta.tail, buf->meta.mask);

		while (head = __atomic_load_n(&buf->meta.head, __ATOMIC_ACQUIRE),
		       tail = buf->meta.tail,
		       tail != head
		       ) {
			n = &buf->slots[tail & mask];
			printf("NOTIFY[%08x-%08x] ty=%04x sy=%04x i=%08x\n",
			       head, tail, n->type, n->subtype, n->info);
			if ((n->info & WATCH_INFO_LENGTH) == 0)
				goto out;

			switch (n->type) {
			case WATCH_TYPE_META:
				if (n->subtype == WATCH_META_REMOVAL_NOTIFICATION)
					printf("REMOVAL of watchpoint %08x\n",
					       n->info & WATCH_INFO_ID);
				break;
			case WATCH_TYPE_KEY_NOTIFY:
				saw_key_change(n);
				break;
			}

			tail += (n->info & WATCH_INFO_LENGTH) >> WATCH_LENGTH_SHIFT;
			__atomic_store_n(&buf->meta.tail, tail, __ATOMIC_RELEASE);
		}
	}

out:
	return 0;
}

/*
 * We're only interested in key insertion events.
 */
static struct watch_notification_filter filter = {
	.nr_filters	= 1,
	.filters = {
		[0] = {
			.type			= WATCH_TYPE_KEY_NOTIFY,
			.subtype_filter[0]	= (1 << NOTIFY_KEY_LINKED),
		},
	}
};

int main(int argc, char *argv[])
{
	struct watch_queue_buffer *buf;
	key_serial_t keyring;
	size_t page_size = sysconf(_SC_PAGESIZE);
	int fd;

	if (argc == 1) {
		keyring = keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring",
					"upcall", 0);
		if (keyring == -1) {
			perror("keyctl_search");
			exit(1);
		}
	} else if (argc == 2) {
		keyring = strtoul(argv[1], NULL, 0);
	} else {
		fprintf(stderr, "Format: test-upcall [<keyring>]\n");
		exit(2);
	}

	/* Create a watch on the keyring to detect the addition of keys. */
	fd = open("/dev/watch_queue", O_RDWR | O_CLOEXEC);
	if (fd == -1) {
		perror("/dev/watch_queue");
		exit(1);
	}

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_SIZE, 1) == -1) {
		perror("/dev/watch_queue(size)");
		exit(1);
	}

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_FILTER, &filter) == -1) {
		perror("/dev/watch_queue(filter)");
		exit(1);
	}

	buf = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	if (keyctl(KEYCTL_WATCH_KEY, keyring, fd, 0x01) == -1) {
		perror("keyctl");
		exit(1);
	}

	return consumer(fd, buf);
}
