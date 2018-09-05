#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Run headers_$1 command for all suitable architectures

# Stop on error
set -e

if ! $CC -x c++ -c - -o /dev/null </dev/null 2>/dev/null
then
    echo "  CHECK   C++ HEADER COMPILATION [SKIPPED]"
    exit 0
fi

echo "  CHECK   C++ HEADER COMPILATION"

mkdir -p hdr-check
cd hdr-check

mkdir -p include/sys
mkdir -p include/arpa
mkdir -p include/xen/interface
echo >include/endian.h
echo >include/limits.h
echo >include/stdint.h
echo >include/stdlib.h
echo >include/stdio.h
echo >include/string.h
echo >include/time.h
echo >include/unistd.h
echo >include/arpa/inet.h
echo >include/sys/ioctl.h
echo >include/sys/types.h
echo >include/sys/time.h
echo >include/sys/socket.h
echo >include/xen/interface/xen.h

cat >test.h <<EOF
#ifdef __cplusplus
#define NULL nullptr
#define _Bool bool
#else
#define NULL ((void *)0)
#define bool _Bool
#endif
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/time.h>

typedef __s8			int8_t;
typedef __s16			int16_t;
typedef __s32			int32_t;
typedef __s64			int64_t;
typedef __u8			uint8_t;
typedef __u16			uint16_t;
typedef __u32			uint32_t;
typedef __u64			uint64_t;
typedef long int		intptr_t;
typedef unsigned long int	uintptr_t;
typedef unsigned short		u_short;
typedef unsigned int		u_int;
typedef unsigned long		u_long;
typedef char			*caddr_t;

typedef __kernel_clockid_t	clockid_t;
typedef __kernel_ino_t		ino_t;
typedef __kernel_pid_t		pid_t;
typedef __kernel_sa_family_t	sa_family_t;
typedef __kernel_size_t		size_t;
typedef __kernel_uid_t		uid_t;

typedef unsigned long		elf_greg_t;
typedef elf_greg_t		elf_gregset_t[1];
typedef unsigned long long	elf_fpregset_t[1];
typedef unsigned long long	elf_fpxregset_t[1];

#define INT_MIN ((int)0x80000000)
#define INT_MAX ((int)0x7fffffff)

extern size_t strlen(const char *);
extern void *memset(void *, int, size_t);
extern void *memcpy(void *, const void *, size_t);
extern __u16 ntohs(__u16);
extern __u16 htons(__u16);
extern __u32 ntohl(__u32);
extern __u32 htonl(__u32);

typedef uint32_t		grant_ref_t;
typedef uint16_t		domid_t;
typedef unsigned long		xen_pfn_t;

#define MSG_FIN         0x200

typedef int SVGA3dMSPattern;
typedef int SVGA3dMSQualityLevel;

struct sockaddr
{
	sa_family_t	sa_family;
	char		sa_data[14];
};
#define sockaddr_storage __kernel_sockaddr_storage

#define _LINUX_PATCHKEY_H_INDIRECT

EOF

find ../usr/include -name '*.h' |
    grep -v 'linux/byteorder/big_endian.h' |
    grep -v 'linux/byteorder/little_endian.h' |
    grep -v '_\(32\|64\|x32\)[.]h$' |
    grep -v '/asm-generic/' |
    # ip*t_LOG.h are deprecated
    grep -v 'linux/netfilter_ipv4/ipt_LOG[.]h' |
    grep -v 'linux/netfilter_ipv6/ip6t_LOG[.]h' |
    sed -e 's!../usr/include/!#include <!' -e 's!$!>!' >>test.h

echo '#include "test.h"' >test.cpp

$CC -x c++ -o /dev/null -c test.cpp \
    -nostdinc \
    -isystem ./include \
    -isystem ../usr/include \
    -fpermissive \
    -D PAGE_SIZE='#PAGE_SIZE_IS_NOT_VALID_OUTSIDE_OF_KERNEL'
