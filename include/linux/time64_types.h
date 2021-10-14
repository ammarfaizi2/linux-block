/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIME64_TYPES_H
#define _LINUX_TIME64_TYPES_H

#include <linux/types.h>
#include <vdso/time64.h>

typedef __s64 time64_t;
typedef __u64 timeu64_t;

#include <uapi/linux/time.h>

struct timespec64 {
	time64_t	tv_sec;			/* seconds */
	long		tv_nsec;		/* nanoseconds */
};

struct itimerspec64 {
	struct timespec64 it_interval;
	struct timespec64 it_value;
};

/* Located here for timespec[64]_valid_strict */
#define TIME64_MAX			((s64)~((u64)1 << 63))
#define TIME64_MIN			(-TIME64_MAX - 1)

#define KTIME_MAX			((s64)~((u64)1 << 63))
#define KTIME_MIN			(-KTIME_MAX - 1)
#define KTIME_SEC_MAX			(KTIME_MAX / NSEC_PER_SEC)
#define KTIME_SEC_MIN			(KTIME_MIN / NSEC_PER_SEC)

/*
 * Limits for settimeofday():
 *
 * To prevent setting the time close to the wraparound point time setting
 * is limited so a reasonable uptime can be accomodated. Uptime of 30 years
 * should be really sufficient, which means the cutoff is 2232. At that
 * point the cutoff is just a small part of the larger problem.
 */
#define TIME_UPTIME_SEC_MAX		(30LL * 365 * 24 *3600)
#define TIME_SETTOD_SEC_MAX		(KTIME_SEC_MAX - TIME_UPTIME_SEC_MAX)

#endif /* _LINUX_TIME64_TYPES_H */
