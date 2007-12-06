#ifndef INDSYSCALL
#ifndef _LINUX_INDIRECT_H
#define _LINUX_INDIRECT_H

#include <asm/indirect.h>
#include <linux/syslet-abi.h>


/* IMPORTANT:
   All the elements of this union must be neutral to the word size
   and must not require reworking when used in compat syscalls.  Used
   fixed-size types or types which are known to not vary in size across
   architectures.  */
union indirect_params {
  struct {
    int flags;
  } file_flags;
  struct syslet_args syslet;
};

#define INDIRECT_PARAM(set, name) current->indirect_params.set.name

#endif
#else

/* Here comes the list of system calls which can be called through
   sys_indirect.  When the list if support system calls is needed the
   file including this header is supposed to define a macro "INDSYSCALL"
   which adds a prefix fitting to the use.  If the resulting macro is
   defined we generate a line
	case MACRO:
   */
#if INDSYSCALL(accept)
  case INDSYSCALL(accept):
#endif
#if INDSYSCALL(socket)
  case INDSYSCALL(socket):
#endif
#if INDSYSCALL(socketcall)
  case INDSYSCALL(socketcall):
#endif
#if INDSYSCALL(socketpair)
  case INDSYSCALL(socketpair):
#endif
  case INDSYSCALL(eventfd):
  case INDSYSCALL(signalfd):
  case INDSYSCALL(timerfd):

#endif
