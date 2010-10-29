#ifndef BINJECT_H
#define BINJECT_H

#define BINJECT_MAGIC		0x89
#define BINJECT_VER		0x01
#define BINJECT_MAGIC_SHIFT	8
#define BINJECT_VER_MASK	((1 << BINJECT_MAGIC_SHIFT) - 1)

struct b_user_cmd {
	u16 magic;	/* INPUT */
	u16 type;	/* INPUT */
	u32 error;	/* OUTPUT */
	u32 flags;	/* INPUT */
	u32 len;	/* INPUT */
	u64 offset;	/* INPUT */
	u64 buf;	/* INPUT */
	u64 usr_ptr;	/* PASSED THROUGH */
	u64 nsec;	/* OUTPUT */
};

struct b_ioctl_cmd {
	int fd;
	int minor;
};

#define BINJECT_IOCTL_CHR	'J'
#define B_IOCTL_ADD		_IOWR(BINJECT_IOCTL_CHR, 1, struct b_ioctl_cmd)
#define B_IOCTL_DEL		_IOWR(BINJECT_IOCTL_CHR, 2, struct b_ioctl_cmd)

enum {
	B_TYPE_READ		= 0,
	B_TYPE_WRITE,
	B_TYPE_DISCARD,
	B_TYPE_READVOID,
	B_TYPE_WRITEZERO,
	B_TYPE_READBARRIER,
	B_TYPE_WRITEBARRIER,
	B_TYPE_NR
};

enum {
	__B_FLAG_SYNC	= 0,
	__B_FLAG_UNPLUG,
	__B_FLAG_NOIDLE,
	__B_FLAG_BARRIER,
	__B_FLAG_META,
	__B_FLAG_RAHEAD,
	__B_FLAG_FAILFAST_DEV,
	__B_FLAG_FAILFAST_TRANSPORT,
	__B_FLAG_FAILFAST_DRIVER,
	__B_FLAG_NR,

	B_FLAG_SYNC			= 1 << __B_FLAG_SYNC,
	B_FLAG_UNPLUG			= 1 << __B_FLAG_UNPLUG,
	B_FLAG_NOIDLE			= 1 << __B_FLAG_NOIDLE,
	B_FLAG_BARRIER			= 1 << __B_FLAG_BARRIER,
	B_FLAG_META			= 1 << __B_FLAG_META,
	B_FLAG_RAHEAD			= 1 << __B_FLAG_RAHEAD,
	B_FLAG_FAILFAST_DEV		= 1 << __B_FLAG_FAILFAST_DEV,
	B_FLAG_FAILFAST_TRANSPORT	= 1 << __B_FLAG_FAILFAST_TRANSPORT,
	B_FLAG_FAILFAST_DRIVER		= 1 << __B_FLAG_FAILFAST_DRIVER,
};

static inline void binject_buc_set_magic(struct b_user_cmd *buc)
{
	buc->magic = (BINJECT_MAGIC << BINJECT_MAGIC_SHIFT) | BINJECT_VER;
}

static inline bool binject_buc_check_magic(struct b_user_cmd *buc)
{
	return ((buc->magic & BINJECT_VER_MASK) == BINJECT_VER) &&
		((buc->magic >> BINJECT_MAGIC_SHIFT) == BINJECT_MAGIC);
}

#endif
