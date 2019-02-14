/* Link a key into a container keyring and grant perms to the container.
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
#include <errno.h>
#include <sys/wait.h>
#include <linux/mount.h>
#include <linux/unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <keyutils.h>

#define KEYCTL_GRANT_PERMISSION		36	/* Grant a permit to a key */

enum key_ace_subject_type {
	KEY_ACE_SUBJ_STANDARD	= 0,	/* subject is one of key_ace_standard_subject */
	KEY_ACE_SUBJ_CONTAINER	= 1,	/* subject is a container fd */
	KEY_ACE_SUBJ_CONTAINER_NAME = 2, /* subject is a container name pointer */
};

enum key_ace_standard_subject {
	KEY_ACE_EVERYONE	= 0,	/* Everyone, including owner and group */
	KEY_ACE_GROUP		= 1,	/* The key's group */
	KEY_ACE_OWNER		= 2,	/* The owner of the key */
	KEY_ACE_POSSESSOR	= 3,	/* Any process that possesses of the key */
};

#define KEY_ACE_VIEW		0x00000001 /* Can describe the key */
#define KEY_ACE_READ		0x00000002 /* Can read the key content */
#define KEY_ACE_WRITE		0x00000004 /* Can update/modify the key content */
#define KEY_ACE_SEARCH		0x00000008 /* Can find the key by search */
#define KEY_ACE_LINK		0x00000010 /* Can make a link to the key */
#define KEY_ACE_SET_SECURITY	0x00000020 /* Can set owner, group, ACL */
#define KEY_ACE_INVAL		0x00000040 /* Can invalidate the key */
#define KEY_ACE_REVOKE		0x00000080 /* Can revoke the key */
#define KEY_ACE_JOIN		0x00000100 /* Can join keyring */
#define KEY_ACE_CLEAR		0x00000200 /* Can clear keyring */

int main(int argc, char *argv[])
{
	key_serial_t key, keyring;

	if (argc == 2) {
		printf("Find keyring '_container'...\n");
		keyring = keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "_container", 0);
		if (keyring == -1) {
			perror("keyctl_search");
			exit(1);
		}

		key = atoi(argv[1]);
	} else if (argc == 3) {
		printf("Use specified keyring...\n");
		keyring = atoi(argv[2]);
		key = atoi(argv[1]);
	} else {
		fprintf(stderr, "Format: test-cont-grant <key> [<cont-keyring>]\n");
		exit(2);
	}

	if (keyctl(KEYCTL_GRANT_PERMISSION, key,
		   KEY_ACE_SUBJ_CONTAINER_NAME, "foo-test",
		   KEY_ACE_SEARCH) < 0) {
		perror("keyctl_grant/s");
		exit(1);
	}

	if (keyctl_link(key, keyring) < 0) {
		perror("keyctl_link");
		exit(1);
	}

	exit(0);
}
