/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ALPHA_TERMIOS_H
#define _ALPHA_TERMIOS_H

#include <linux/uaccess.h>
#include <uapi/asm/termios.h>

/*	eof=^D		eol=\0		eol2=\0		erase=del
	werase=^W	kill=^U		reprint=^R	sxtc=\0
	intr=^C		quit=^\		susp=^Z		<OSF/1 VDSUSP>
	start=^Q	stop=^S		lnext=^V	discard=^U
	vmin=\1		vtime=\0
*/
#define INIT_C_CC "\004\000\000\177\027\025\022\000\003\034\032\000\021\023\026\025\001\000"

/*
 * Translate a "termio" structure into a "termios". Ugh.
 */

static inline int user_termio_to_kernel_termios(struct ktermios *termios,
						struct termio __user *termio)
{
	struct termio v;
	bool canon;

	if (copy_from_user(&v, termio, sizeof(struct termio)))
		return -EFAULT;

	termios->c_iflag = (0xffff0000 & termios->c_iflag) | v.c_iflag;
	termios->c_oflag = (0xffff0000 & termios->c_oflag) | v.c_oflag;
	termios->c_cflag = (0xffff0000 & termios->c_cflag) | v.c_cflag;
	termios->c_lflag = (0xffff0000 & termios->c_lflag) | v.c_lflag;
	termios->c_line = (0xffff0000 & termios->c_lflag) | v.c_line;

	canon = v.c_lflag & ICANON;
	termios->c_cc[VINTR]  = v.c_cc[_VINTR];
	termios->c_cc[VQUIT]  = v.c_cc[_VQUIT];
	termios->c_cc[VERASE] = v.c_cc[_VERASE];
	termios->c_cc[VKILL]  = v.c_cc[_VKILL];
	termios->c_cc[VEOL2]  = v.c_cc[_VEOL2];
	termios->c_cc[VSWTC]  = v.c_cc[_VSWTC];
	termios->c_cc[canon ? VEOF : VMIN]  = v.c_cc[_VEOF];
	termios->c_cc[canon ? VEOL : VTIME] = v.c_cc[_VEOL];

	return 0;
}
#define user_termio_to_kernel_termios user_termio_to_kernel_termios

/*
 * Translate a "termios" structure into a "termio". Ugh.
 *
 * Note the "fun" _VMIN overloading.
 */
static inline int kernel_termios_to_user_termio(struct termio __user *termio,
						struct ktermios *termios)
{
	struct termio v;
	bool canon;

	memset(&v, 0, sizeof(struct termio));
	v.c_iflag = termios->c_iflag;
	v.c_oflag = termios->c_oflag;
	v.c_cflag = termios->c_cflag;
	v.c_lflag = termios->c_lflag;
	v.c_line = termios->c_line;

	canon = v.c_lflag & ICANON;
	v.c_cc[_VINTR]  = termios->c_cc[VINTR];
	v.c_cc[_VQUIT]  = termios->c_cc[VQUIT];
	v.c_cc[_VERASE] = termios->c_cc[VERASE];
	v.c_cc[_VKILL]  = termios->c_cc[VKILL];
	v.c_cc[_VEOF]   = termios->c_cc[canon ? VEOF : VMIN];
	v.c_cc[_VEOL]   = termios->c_cc[canon ? VEOL : VTIME];
	v.c_cc[_VEOL2]  = termios->c_cc[VEOL2];
	v.c_cc[_VSWTC]  = termios->c_cc[VSWTC];

	return copy_to_user(termio, &v, sizeof(struct termio));
}
#define kernel_termios_to_user_termio kernel_termios_to_user_termio

#endif	/* _ALPHA_TERMIOS_H */
