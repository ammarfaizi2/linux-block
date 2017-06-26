/*
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2017 Cavium Networks.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_SIGNAL_COMMON_H
#define __ASM_SIGNAL_COMMON_H

#include <linux/uaccess.h>
#include <asm/fpsimd.h>

#define EXTRA_CONTEXT_SIZE round_up(sizeof(struct extra_context), 16)
#define TERMINATOR_SIZE round_up(sizeof(struct _aarch64_ctx), 16)

/*
 * Sanity limit on the approximate maximum size of signal frame we'll
 * try to generate.  Stack alignment padding and the frame record are
 * not taken into account.  This limit is not a guarantee and is
 * NOT ABI.
 */
#define SIGFRAME_MAXSZ SZ_64K

#define parse_user_sigcontext(user, sf)					\
	__parse_user_sigcontext(user, &(sf)->uc.uc_mcontext, sf)

struct user_ctxs {
	struct fpsimd_context __user *fpsimd;
};

struct frame_record {
	u64 fp;
	u64 lr;
};
struct rt_sigframe_user_layout;

int setup_extra_context(char __user *sfp, unsigned long users, char __user *userp);
int __parse_user_sigcontext(struct user_ctxs *user,
				   struct sigcontext __user const *sc,
				   void __user const *sigframe_base);

int preserve_fpsimd_context(struct fpsimd_context __user *ctx);
int restore_fpsimd_context(struct fpsimd_context __user *ctx);

#endif /* __ASM_SIGNAL_COMMON_H */
