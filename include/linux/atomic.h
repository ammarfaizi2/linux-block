#ifndef _LINUX_ATOMIC_H
#define _LINUX_ATOMIC_H

#include <linux/atomic_types.h>

#ifndef CONFIG_64BIT
# include <linux/atomic_api.h>
#endif

#endif
