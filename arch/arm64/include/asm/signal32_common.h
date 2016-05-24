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
#ifndef __ASM_SIGNAL32_COMMON_H
#define __ASM_SIGNAL32_COMMON_H

#ifdef CONFIG_COMPAT

int copy_siginfo_to_user32(compat_siginfo_t __user *to, const siginfo_t *from);
int copy_siginfo_from_user32(siginfo_t *to, compat_siginfo_t __user *from);

int put_sigset_t(compat_sigset_t __user *uset, sigset_t *set);
int get_sigset_t(sigset_t *set, const compat_sigset_t __user *uset);

#endif /* CONFIG_COMPAT*/

#endif /* __ASM_SIGNAL32_COMMON_H */
