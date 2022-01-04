/*
 * We generate the PER_TASK_OFFSET_ offsets early during the build, using this file.
 */

#include <linux/kbuild.h>

#define DEF_PER_TASK(name)		DEFINE(PER_TASK_OFFSET__##name, offsetof(struct task_struct_per_task, name))

#define DEF(type, name)			DEF_PER_TASK(name)
#define DEF_A(type, name, size)		DEF_PER_TASK(name)


void __used per_task_common(void)
{
#include "per_task_area_struct_template.h"
}

#undef DEF_A
#undef DEF

