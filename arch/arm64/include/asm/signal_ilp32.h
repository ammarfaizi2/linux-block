/*
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

#include <asm/signal32_common.h>
#include <asm/signal_common.h>

#ifndef __ASM_SIGNAL_ILP32_H
#define __ASM_SIGNAL_ILP32_H

#ifdef CONFIG_ARM64_ILP32

#include <linux/compat.h>

int ilp32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs);

#else

static inline int ilp32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs)
{
	return -ENOSYS;
}

#endif /* CONFIG_ARM64_ILP32 */

#endif /* __ASM_SIGNAL_ILP32_H */
