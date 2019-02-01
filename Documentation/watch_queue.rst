============================
Mappable notifications queue
============================

This is a misc device that acts as a mapped ring buffer by which userspace can
receive notifications from the kernel.  This is can be used in conjunction
with::

  * Key/keyring notifications

  * Mount topology change notifications

  * Superblock event notifications


The notifications buffers can be enabled by:

	"Device Drivers"/"Misc devices"/"Mappable notification queue"
	(CONFIG_WATCH_QUEUE)

This document has the following sections:

.. contents:: :local:


Overview
========

This facility appears as a misc device file that is opened and then mapped and
polled.  Each time it is opened, it creates a new buffer specific to the
returned file descriptor.  Then, when the opening process sets watches, it
indicates that particular buffer it wants notifications from that watch to be
written into.  Note that there are no read() and write() methods (except for
debugging).  The user is expected to access the ring directly and to use poll
to wait for new data.

If a watch is in place, notifications are only written into the buffer if the
filter criteria are passed and if there's sufficient space available in the
ring.  If neither of those is so, a notification will be discarded.  In the
latter case, an overrun indicator will also be set.

Note that when producing a notification, the kernel does not wait for the
consumers to collect it, but rather just continues on.  This means that
notifications can be generated whilst spinlocks are held and also protects the
kernel from being held up indefinitely by a userspace malfunction.

As far as the ring goes, the head index belongs to the kernel and the tail
index belongs to userspace.  The kernel will refuse to write anything if the
tail index becomes invalid.  Userspace *must* use appropriate memory barriers
between reading or updating the tail index and reading the ring.


Record Structure
================

Notification records in the ring may occupy a variable number of slots within
the buffer, beginning with a 1-slot header::

	struct watch_notification {
		__u16	type;
		__u16	subtype;
		__u32	info;
	};

"type" indicates the source of the notification record and "subtype" indicates
the type of record from that source (see the Watch Sources section below).  The
type may also be "WATCH_TYPE_META".  This is a special record type generated
internally by the watch queue driver itself.  There are two subtypes, one of
which indicates records that should be just skipped (padding or metadata):

    * WATCH_META_SKIP_NOTIFICATION
    * WATCH_META_REMOVAL_NOTIFICATION

The former indicates a record that should just be skipped and the latter
indicates that an object on which a watchpoint was installed was removed or
destroyed.

"info" indicates a bunch of things, including:

  * The length of the record (mask with WATCH_INFO_LENGTH).  This indicates the
    size of the record, which may be between 1 and 63 slots.  Note that this is
    placed appropriately within the info value so that no shifting is required
    to convert number of occupied slots to byte length.

  * The watchpoint ID (mask with WATCH_INFO_ID).  This indicates that caller's
    ID of the watchpoint, which may be between 0 and 255.  Multiple watchpoints
    may share a queue, and this provides a means to distinguish them.

  * A buffer overrun flag (WATCH_INFO_OVERRUN flag).  If this is set in a
    notification record, some of the preceding records were discarded.

  * An ENOMEM-loss flag (WATCH_INFO_ENOMEM flag).  This is set to indicate that
    an event was lost to ENOMEM.

  * A recursive-change flag (WATCH_INFO_RECURSIVE flag).  This is set to
    indicate that the change that happened was recursive - for instance
    changing the attributes on an entire mount subtree.

  * An exact-match flag (WATCH_INFO_IN_SUBTREE flag).  This is set if the event
    didn't happen exactly at the watchpoint, but rather somewhere in the
    subtree thereunder.

  * Some type-specific flags (WATCH_INFO_TYPE_FLAGS).  These are set by the
    notification producer to indicate some meaning to the kernel.

Everything in info apart from the length can be used for filtering.


Ring Structure
==============

The ring is divided into 8-byte slots.  The caller uses an ioctl() to set the
size of the ring after opening and this must be a power-of-2 multiple of the
system page size (so that the mask can be used with AND).

The head and tail indices are stored in the first two slots in the ring, which
are marked out as a skippable entry::

	struct watch_queue_buffer {
		union {
			struct {
				struct watch_notification watch;
				volatile __u32	head;
				volatile __u32	tail;
				__u32		mask;
			} meta;
			struct watch_notification slots[0];
		};
	};

In "meta.watch", type will be set to WATCH_TYPE_META and subtype to
WATCH_META_SKIP_NOTIFICATION so that anyone processing the buffer will just
skip this record.  Also, because this record is here, records cannot wrap round
the end of the buffer, so a skippable padding element will be inserted at the
end of the buffer if needed.  Thus the contents of a notification record in the
buffer are always contiguous.

"meta.mask" is an AND'able mask to turn the index counters into slots array
indices.

The buffer is empty if "meta.head" == "meta.tail".

[!] NOTE that the ring indices "meta.head" and "meta.tail" are indices into
"slots[]" not byte offsets into the buffer.

[!] NOTE that userspace must never change the head pointer.  This belongs to
the kernel and will be updated by that.  The kernel will never change the tail
pointer.

[!] NOTE that userspace must never AND-off the tail pointer before updating it,
but should just keep adding to it and letting it wrap naturally.  The value
*should* be masked off when used as an index into slots[].

[!] NOTE that if the distance between head and tail becomes too great, the
kernel will assume the buffer is full and write no more until the issue is
resolved.


Watch Sources
=============

Any particular buffer can be fed from multiple sources.  Sources include:

  * WATCH_TYPE_MOUNT_NOTIFY

    Notifications of this type indicate mount tree topology changes and mount
    attribute changes.  A watchpoint can be set on a particular file or
    directory and notifications from the path subtree rooted at that point will
    be intercepted.

  * WATCH_TYPE_SB_NOTIFY

    Notifications of this type indicate superblock events, such as quota limits
    being hit, I/O errors being produced or network server loss/reconnection.
    Watchpoints of this type are set directly on superblocks.

  * WATCH_TYPE_KEY_NOTIFY

    Notifications of this type indicate changes to keys and keyrings, including
    the changes of keyring contents or the attributes of keys.

    See Documentation/security/keys/core.rst for more information.


Configuring Watchpoints
=======================

When a watchpoint is set up, the caller assigns an ID and can set filtering
parameters.  The following structure is filled out and passed to the
watchpoint creation system call::

	struct watch_notification_filter {
		__u64	subtype_filter[4];
		__u32	info_filter;
		__u32	info_mask;
		__u32	info_id;
		__u32	__reserved;
	};

"subtype_filter" is a bitmask indicating the subtypes that are of interest.  In
this version of the structure, only the first 256 subtypes are supported.  Bit
0 of subtype_filter[0] corresponds to subtype 0, bit 1 to subtype 1, and so on.

"info_filter" and "info_mask" act as a filter on the info field of the
notification record.  The notification is only written into the buffer if::

	(watch.info & info_mask) == info_filter

This can be used, for example, to ignore events that are not exactly on the
watched point in a mount tree by specifying WATCH_INFO_IN_SUBTREE must be 0.

"info_id" is OR'd into watch.info.  This indicates the watchpoint ID in the top
8 bits.  All bits outside of WATCH_INFO_ID must be 0.

"__reserved" must be 0.

If the pointer to this structure is NULL, this indicates to the system call
that the watchpoint should be removed.


Polling
=======

The file descriptor that holds the buffer may be used with poll() and similar.
POLLIN and POLLRDNORM are set if the buffer indices differ.  POLLERR is set if
the buffer indices are further apart than the size of the buffer.  Wake-up
events are only generated if the buffer is transitioned from an empty state.


Example
=======

A buffer is created with something like the following::

	fd = open("/dev/watch_queue", O_RDWR);

	#define BUF_SIZE 4
	ioctl(fd, IOC_WATCH_QUEUE_SET_SIZE, BUF_SIZE);

	page_size = sysconf(_SC_PAGESIZE);
	buf = mmap(NULL, BUF_SIZE * page_size,
		   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

It can then be set to receive mount topology change notifications, keyring
change notifications and superblock notifications::

	memset(&filter, 0, sizeof(filter));
	filter.subtype_filter[0] = ~0ULL;
	filter.info_mask	 = WATCH_INFO_IN_SUBTREE;
	filter.info_filter	 = 0;
	filter.info_id		 = 0x01000000;

	keyctl(KEYCTL_WATCH_KEY, KEY_SPEC_SESSION_KEYRING, fd, &filter);

	mount_notify(AT_FDCWD, "/", 0, fd, &filter);

	sb_notify(AT_FDCWD, "/", 0, fd, &filter);

The notifications can then be consumed by something like the following::

	extern void saw_mount_change(struct watch_notification *n);
	extern void saw_key_change(struct watch_notification *n);

	static int consumer(int fd, struct watch_queue_buffer *buf)
	{
		struct watch_notification *n;
		struct pollfd p[1];
		unsigned int head, tail, mask = buf->meta.mask;

		for (;;) {
			p[0].fd = fd;
			p[0].events = POLLIN | POLLERR;
			p[0].revents = 0;

			if (poll(p, 1, -1) == -1 || p[0].revents & POLLERR)
				goto went_wrong;

			while (head = _atomic_load_acquire(buf->meta.head),
			       tail = buf->meta.tail,
			       tail != head
			       ) {
				n = &buf->slots[tail & mask];
				if ((n->info & WATCH_INFO_LENGTH) == 0)
					goto went_wrong;

				switch (n->type) {
				case WATCH_TYPE_MOUNT_NOTIFY:
					saw_mount_change(n);
					break;
				case WATCH_TYPE_KEY_NOTIFY:
					saw_key_change(n);
					break;
				}

				tail += (n->info & WATCH_INFO_LENGTH) >> WATCH_LENGTH_SHIFT;
				_atomic_store_release(buf->meta.tail, tail);
			}
		}

	went_wrong:
		return 0;
	}

Note the memory barriers when loading the head pointer and storing the tail
pointer!
