/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SPARC_TERMIOS_H
#define _SPARC_TERMIOS_H

#include <uapi/asm/termios.h>
#include <linux/uaccess.h>


/*
 * c_cc characters in the termio structure.  Oh, how I love being
 * backwardly compatible.  Notice that character 4 and 5 are
 * interpreted differently depending on whether ICANON is set in
 * c_lflag.  If it's set, they are used as _VEOF and _VEOL, otherwise
 * as _VMIN and V_TIME.  This is for compatibility with OSF/1 (which
 * is compatible with sysV)...
 */
#define _VMIN	4
#define _VTIME	5

/*	intr=^C		quit=^\		erase=del	kill=^U
	eof=^D		eol=\0		eol2=\0		sxtc=\0
	start=^Q	stop=^S		susp=^Z		dsusp=^Y
	reprint=^R	discard=^U	werase=^W	lnext=^V
	vmin=\1         vtime=\0
*/
#define INIT_C_CC "\003\034\177\025\004\000\000\000\021\023\032\031\022\025\027\026\001"

/*
 * Translate a "termios" structure into a "termio". Ugh.
 *
 * Note the "fun" _VMIN overloading.
 */
static inline int kernel_termios_to_user_termio(struct termio __user *termio,
						struct ktermios *termios)
{
	struct termio v;
	memset(&v, 0, sizeof(struct termio));
	v.c_iflag = termios->c_iflag;
	v.c_oflag = termios->c_oflag;
	v.c_cflag = termios->c_cflag;
	v.c_lflag = termios->c_lflag;
	v.c_line = termios->c_line;
	memcpy(v.c_cc, termios->c_cc, NCC);
	if (!(v.c_lflag & ICANON)) {
		v.c_cc[_VMIN] = termios->c_cc[VMIN];
		v.c_cc[_VTIME] = termios->c_cc[VTIME];
	}
	return copy_to_user(termio, &v, sizeof(struct termio));
}
#define kernel_termios_to_user_termio kernel_termios_to_user_termio

static inline int user_termios_to_kernel_termios(struct ktermios *k,
						 struct termios2 __user *u)
{
	int err;
	err  = get_user(k->c_iflag, &u->c_iflag);
	err |= get_user(k->c_oflag, &u->c_oflag);
	err |= get_user(k->c_cflag, &u->c_cflag);
	err |= get_user(k->c_lflag, &u->c_lflag);
	err |= get_user(k->c_line,  &u->c_line);
	err |= copy_from_user(k->c_cc, u->c_cc, NCCS);
	if (k->c_lflag & ICANON) {
		err |= get_user(k->c_cc[VEOF], &u->c_cc[VEOF]);
		err |= get_user(k->c_cc[VEOL], &u->c_cc[VEOL]);
	} else {
		err |= get_user(k->c_cc[VMIN],  &u->c_cc[_VMIN]);
		err |= get_user(k->c_cc[VTIME], &u->c_cc[_VTIME]);
	}
	err |= get_user(k->c_ispeed,  &u->c_ispeed);
	err |= get_user(k->c_ospeed,  &u->c_ospeed);
	return err;
}

#define user_termios_to_kernel_termios user_termios_to_kernel_termios

static inline int kernel_termios_to_user_termios(struct termios2 __user *u,
						 struct ktermios *k)
{
	int err;
	err  = put_user(k->c_iflag, &u->c_iflag);
	err |= put_user(k->c_oflag, &u->c_oflag);
	err |= put_user(k->c_cflag, &u->c_cflag);
	err |= put_user(k->c_lflag, &u->c_lflag);
	err |= put_user(k->c_line, &u->c_line);
	err |= copy_to_user(u->c_cc, k->c_cc, NCCS);
	if (!(k->c_lflag & ICANON)) {
		err |= put_user(k->c_cc[VMIN],  &u->c_cc[_VMIN]);
		err |= put_user(k->c_cc[VTIME], &u->c_cc[_VTIME]);
	} else {
		err |= put_user(k->c_cc[VEOF], &u->c_cc[VEOF]);
		err |= put_user(k->c_cc[VEOL], &u->c_cc[VEOL]);
	}
	err |= put_user(k->c_ispeed, &u->c_ispeed);
	err |= put_user(k->c_ospeed, &u->c_ospeed);
	return err;
}

#define kernel_termios_to_user_termios kernel_termios_to_user_termios

static inline int user_termios_to_kernel_termios_1(struct ktermios *k,
						 struct termios __user *u)
{
	int err;
	err  = get_user(k->c_iflag, &u->c_iflag);
	err |= get_user(k->c_oflag, &u->c_oflag);
	err |= get_user(k->c_cflag, &u->c_cflag);
	err |= get_user(k->c_lflag, &u->c_lflag);
	err |= get_user(k->c_line,  &u->c_line);
	err |= copy_from_user(k->c_cc, u->c_cc, NCCS);
	if (k->c_lflag & ICANON) {
		err |= get_user(k->c_cc[VEOF], &u->c_cc[VEOF]);
		err |= get_user(k->c_cc[VEOL], &u->c_cc[VEOL]);
	} else {
		err |= get_user(k->c_cc[VMIN],  &u->c_cc[_VMIN]);
		err |= get_user(k->c_cc[VTIME], &u->c_cc[_VTIME]);
	}
	return err;
}

#define user_termios_to_kernel_termios_1 user_termios_to_kernel_termios_1

static inline int kernel_termios_to_user_termios_1(struct termios __user *u,
						 struct ktermios *k)
{
	int err;
	err  = put_user(k->c_iflag, &u->c_iflag);
	err |= put_user(k->c_oflag, &u->c_oflag);
	err |= put_user(k->c_cflag, &u->c_cflag);
	err |= put_user(k->c_lflag, &u->c_lflag);
	err |= put_user(k->c_line, &u->c_line);
	err |= copy_to_user(u->c_cc, k->c_cc, NCCS);
	if (!(k->c_lflag & ICANON)) {
		err |= put_user(k->c_cc[VMIN],  &u->c_cc[_VMIN]);
		err |= put_user(k->c_cc[VTIME], &u->c_cc[_VTIME]);
	} else {
		err |= put_user(k->c_cc[VEOF], &u->c_cc[VEOF]);
		err |= put_user(k->c_cc[VEOL], &u->c_cc[VEOL]);
	}
	return err;
}

#define kernel_termios_to_user_termios_1 kernel_termios_to_user_termios_1

#endif /* _SPARC_TERMIOS_H */
