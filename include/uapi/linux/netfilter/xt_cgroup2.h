#ifndef _XT_CGROUP2_H
#define _XT_CGROUP2_H

#include <linux/types.h>
#include <linux/limits.h>

struct xt_cgroup2_info {
	char		path[PATH_MAX];
	__u8		invert;

	/* kernel internal data */
	void		*priv __attribute__((aligned(8)));
};

#endif /* _XT_CGROUP2_H */
