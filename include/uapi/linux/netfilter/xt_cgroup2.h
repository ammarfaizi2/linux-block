#ifndef _XT_CGROUP2_H
#define _XT_CGROUP2_H

#include <linux/types.h>

struct xt_cgroup2_info {
	char				path[PATH_MAX];
	__u8				invert;

	/* kernel internal data */
	void				*priv;
};

#endif /* _XT_CGROUP2_H */
