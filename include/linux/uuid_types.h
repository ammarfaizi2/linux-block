/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_UUID_TYPES_H_
#define _LINUX_UUID_TYPES_H_

#include <uapi/linux/uuid.h>

#define UUID_SIZE 16

typedef struct {
	__u8 b[UUID_SIZE];
} uuid_t;

/*
 * The length of a UUID string ("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
 * not including trailing NUL.
 */
#define	UUID_STRING_LEN		36

#endif
