#ifndef _LINUX_INDIRECT_H
#define _LINUX_INDIRECT_H

#include <asm/indirect.h>


/* IMPORTANT:
   All the elements of this union must be neutral to the word size
   and must not require reworking when used in compat syscalls.  Used
   fixed-size types or types which are known to not vary in size across
   architectures.  */
union indirect_params {
};

#define INDIRECT_PARAM(set, name) current->indirect_params.set.name

#endif
