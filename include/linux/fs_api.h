/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_API_H
#define _LINUX_FS_API_H

#include <linux/atomic_api.h>
#include <linux/fs_types.h>

#include <linux/mnt_idmapping.h>
#include <linux/stat.h>
#include <linux/lockdep_api.h>
#include <linux/rwsem_api.h>
#include <linux/kdev_t.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/list_lru.h>
#include <linux/xarray_types.h>
#include <linux/pid_types.h>
#include <linux/fcntl.h>
#include <linux/atomic.h>
#include <linux/migrate_mode.h>
#include <linux/uuid.h>
#include <linux/errseq.h>
#include <linux/mount.h>
#include <linux/quota_types.h>
#include <linux/rbtree.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/wait_types.h>
#include <linux/llist.h>

#include <uapi/linux/fs.h>

extern void inode_init(void);
extern void inode_init_early(void);
extern void files_init(void);
extern void files_maxfiles_init(void);

extern unsigned long get_max_files(void);
/*
 * pagecache_write_begin/pagecache_write_end must be used by general code
 * to write into the pagecache.
 */
int pagecache_write_begin(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata);

int pagecache_write_end(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata);

/*
 * Returns true if any of the pages in the mapping are marked with the tag.
 */
#define mapping_tagged(mapping, tag) xa_marked(&(mapping)->i_pages, tag)

static inline void i_mmap_lock_write(struct address_space *mapping)
{
	down_write(&mapping->i_mmap_rwsem);
}

static inline int i_mmap_trylock_write(struct address_space *mapping)
{
	return down_write_trylock(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_unlock_write(struct address_space *mapping)
{
	up_write(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_lock_read(struct address_space *mapping)
{
	down_read(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_unlock_read(struct address_space *mapping)
{
	up_read(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_assert_locked(struct address_space *mapping)
{
	lockdep_assert_held(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_assert_write_locked(struct address_space *mapping)
{
	lockdep_assert_held_write(&mapping->i_mmap_rwsem);
}

/*
 * Might pages of this file be mapped into userspace?
 */
static inline int mapping_mapped(struct address_space *mapping)
{
	return	!RB_EMPTY_ROOT(&mapping->i_mmap.rb_root);
}

/*
 * Might pages of this file have been modified in userspace?
 * Note that i_mmap_writable counts all VM_SHARED vmas: do_mmap
 * marks vma as VM_SHARED if it is shared, and the file was opened for
 * writing i.e. vma may be mprotected writable even if now readonly.
 *
 * If i_mmap_writable is negative, no new writable mappings are allowed. You
 * can only deny writable mappings, if none exists right now.
 */
static inline int mapping_writably_mapped(struct address_space *mapping)
{
	return atomic_read(&mapping->i_mmap_writable) > 0;
}

static inline int mapping_map_writable(struct address_space *mapping)
{
	return atomic_inc_unless_negative(&mapping->i_mmap_writable) ?
		0 : -EPERM;
}

static inline void mapping_unmap_writable(struct address_space *mapping)
{
	atomic_dec(&mapping->i_mmap_writable);
}

static inline int mapping_deny_writable(struct address_space *mapping)
{
	return atomic_dec_unless_positive(&mapping->i_mmap_writable) ?
		0 : -EBUSY;
}

static inline void mapping_allow_writable(struct address_space *mapping)
{
	atomic_inc(&mapping->i_mmap_writable);
}

static inline struct posix_acl *
uncached_acl_sentinel(struct task_struct *task)
{
	return (void *)task + 1;
}

static inline bool
is_uncached_acl(struct posix_acl *acl)
{
	return (long)acl & 1;
}

struct timespec64 timestamp_truncate(struct timespec64 t, struct inode *inode);

static inline unsigned int i_blocksize(const struct inode *node)
{
	return (1 << node->i_blkbits);
}

/*
 * __mark_inode_dirty expects inodes to be hashed.  Since we don't
 * want special inodes in the fileset inode space, we make them
 * appear hashed, but do not put on any lists.  hlist_del()
 * will work fine and require no locking.
 */
static inline void inode_fake_hash(struct inode *inode)
{
	hlist_add_fake(&inode->i_hash);
}

static inline void inode_lock(struct inode *inode)
{
	down_write(&inode->i_rwsem);
}

static inline void inode_unlock(struct inode *inode)
{
	up_write(&inode->i_rwsem);
}

static inline void inode_lock_shared(struct inode *inode)
{
	down_read(&inode->i_rwsem);
}

static inline void inode_unlock_shared(struct inode *inode)
{
	up_read(&inode->i_rwsem);
}

static inline int inode_trylock(struct inode *inode)
{
	return down_write_trylock(&inode->i_rwsem);
}

static inline int inode_trylock_shared(struct inode *inode)
{
	return down_read_trylock(&inode->i_rwsem);
}

static inline int inode_is_locked(struct inode *inode)
{
	return rwsem_is_locked(&inode->i_rwsem);
}

static inline void inode_lock_nested(struct inode *inode, unsigned subclass)
{
	down_write_nested(&inode->i_rwsem, subclass);
}

static inline void inode_lock_shared_nested(struct inode *inode, unsigned subclass)
{
	down_read_nested(&inode->i_rwsem, subclass);
}

static inline void filemap_invalidate_lock(struct address_space *mapping)
{
	down_write(&mapping->invalidate_lock);
}

static inline void filemap_invalidate_unlock(struct address_space *mapping)
{
	up_write(&mapping->invalidate_lock);
}

static inline void filemap_invalidate_lock_shared(struct address_space *mapping)
{
	down_read(&mapping->invalidate_lock);
}

static inline int filemap_invalidate_trylock_shared(
					struct address_space *mapping)
{
	return down_read_trylock(&mapping->invalidate_lock);
}

static inline void filemap_invalidate_unlock_shared(
					struct address_space *mapping)
{
	up_read(&mapping->invalidate_lock);
}

void lock_two_nondirectories(struct inode *, struct inode*);
void unlock_two_nondirectories(struct inode *, struct inode*);

void filemap_invalidate_lock_two(struct address_space *mapping1,
				 struct address_space *mapping2);
void filemap_invalidate_unlock_two(struct address_space *mapping1,
				   struct address_space *mapping2);


/*
 * NOTE: unlike i_size_read(), i_size_write() does need locking around it
 * (normally i_mutex), otherwise on 32bit/SMP an update of i_size_seqcount
 * can be lost, resulting in subsequent i_size_read() calls spinning forever.
 */
static inline void i_size_write(struct inode *inode, loff_t i_size)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	preempt_disable();
	write_seqcount_begin(&inode->i_size_seqcount);
	inode->i_size = i_size;
	write_seqcount_end(&inode->i_size_seqcount);
	preempt_enable();
#elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPTION)
	preempt_disable();
	inode->i_size = i_size;
	preempt_enable();
#else
	inode->i_size = i_size;
#endif
}

static inline unsigned iminor(const struct inode *inode)
{
	return MINOR(inode->i_rdev);
}

static inline unsigned imajor(const struct inode *inode)
{
	return MAJOR(inode->i_rdev);
}

/*
 * Check if @index falls in the readahead windows.
 */
static inline int ra_has_index(struct file_ra_state *ra, pgoff_t index)
{
	return (index >= ra->start &&
		index <  ra->start + ra->size);
}

static inline struct file *get_file(struct file *f)
{
	atomic_long_inc(&f->f_count);
	return f;
}
#define get_file_rcu_many(x, cnt)	\
	atomic_long_add_unless(&(x)->f_count, (cnt), 0)
#define get_file_rcu(x) get_file_rcu_many((x), 1)
#define file_count(x)	atomic_long_read(&(x)->f_count)

struct net;
void locks_start_grace(struct net *, struct lock_manager *);
void locks_end_grace(struct lock_manager *);
bool locks_in_grace(struct net *);
bool opens_in_grace(struct net *);

/* that will die - we need it for nfs_lock_info */
#include <linux/nfs_fs_i.h>

extern void send_sigio(struct fown_struct *fown, int fd, int band);

#define locks_inode(f) file_inode(f)

#ifdef CONFIG_FILE_LOCKING
extern int fcntl_getlk(struct file *, unsigned int, struct flock *);
extern int fcntl_setlk(unsigned int, struct file *, unsigned int,
			struct flock *);

#if BITS_PER_LONG == 32
extern int fcntl_getlk64(struct file *, unsigned int, struct flock64 *);
extern int fcntl_setlk64(unsigned int, struct file *, unsigned int,
			struct flock64 *);
#endif

extern int fcntl_setlease(unsigned int fd, struct file *filp, long arg);
extern int fcntl_getlease(struct file *filp);

/* fs/locks.c */
void locks_free_lock_context(struct inode *inode);
void locks_free_lock(struct file_lock *fl);
extern void locks_init_lock(struct file_lock *);
extern struct file_lock * locks_alloc_lock(void);
extern void locks_copy_lock(struct file_lock *, struct file_lock *);
extern void locks_copy_conflock(struct file_lock *, struct file_lock *);
extern void locks_remove_posix(struct file *, fl_owner_t);
extern void locks_remove_file(struct file *);
extern void locks_release_private(struct file_lock *);
extern void posix_test_lock(struct file *, struct file_lock *);
extern int posix_lock_file(struct file *, struct file_lock *, struct file_lock *);
extern int locks_delete_block(struct file_lock *);
extern int vfs_test_lock(struct file *, struct file_lock *);
extern int vfs_lock_file(struct file *, unsigned int, struct file_lock *, struct file_lock *);
extern int vfs_cancel_lock(struct file *filp, struct file_lock *fl);
extern int locks_lock_inode_wait(struct inode *inode, struct file_lock *fl);
extern int __break_lease(struct inode *inode, unsigned int flags, unsigned int type);
extern void lease_get_mtime(struct inode *, struct timespec64 *time);
extern int generic_setlease(struct file *, long, struct file_lock **, void **priv);
extern int vfs_setlease(struct file *, long, struct file_lock **, void **);
extern int lease_modify(struct file_lock *, int, struct list_head *);

struct notifier_block;
extern int lease_register_notifier(struct notifier_block *);
extern void lease_unregister_notifier(struct notifier_block *);

struct files_struct;
extern void show_fd_locks(struct seq_file *f,
			 struct file *filp, struct files_struct *files);
#else /* !CONFIG_FILE_LOCKING */
static inline int fcntl_getlk(struct file *file, unsigned int cmd,
			      struct flock __user *user)
{
	return -EINVAL;
}

static inline int fcntl_setlk(unsigned int fd, struct file *file,
			      unsigned int cmd, struct flock __user *user)
{
	return -EACCES;
}

#if BITS_PER_LONG == 32
static inline int fcntl_getlk64(struct file *file, unsigned int cmd,
				struct flock64 *user)
{
	return -EINVAL;
}

static inline int fcntl_setlk64(unsigned int fd, struct file *file,
				unsigned int cmd, struct flock64 *user)
{
	return -EACCES;
}
#endif
static inline int fcntl_setlease(unsigned int fd, struct file *filp, long arg)
{
	return -EINVAL;
}

static inline int fcntl_getlease(struct file *filp)
{
	return F_UNLCK;
}

static inline void
locks_free_lock_context(struct inode *inode)
{
}

static inline void locks_init_lock(struct file_lock *fl)
{
	return;
}

static inline void locks_copy_conflock(struct file_lock *new, struct file_lock *fl)
{
	return;
}

static inline void locks_copy_lock(struct file_lock *new, struct file_lock *fl)
{
	return;
}

static inline void locks_remove_posix(struct file *filp, fl_owner_t owner)
{
	return;
}

static inline void locks_remove_file(struct file *filp)
{
	return;
}

static inline void posix_test_lock(struct file *filp, struct file_lock *fl)
{
	return;
}

static inline int posix_lock_file(struct file *filp, struct file_lock *fl,
				  struct file_lock *conflock)
{
	return -ENOLCK;
}

static inline int locks_delete_block(struct file_lock *waiter)
{
	return -ENOENT;
}

static inline int vfs_test_lock(struct file *filp, struct file_lock *fl)
{
	return 0;
}

static inline int vfs_lock_file(struct file *filp, unsigned int cmd,
				struct file_lock *fl, struct file_lock *conf)
{
	return -ENOLCK;
}

static inline int vfs_cancel_lock(struct file *filp, struct file_lock *fl)
{
	return 0;
}

static inline int locks_lock_inode_wait(struct inode *inode, struct file_lock *fl)
{
	return -ENOLCK;
}

static inline int __break_lease(struct inode *inode, unsigned int mode, unsigned int type)
{
	return 0;
}

static inline void lease_get_mtime(struct inode *inode,
				   struct timespec64 *time)
{
	return;
}

static inline int generic_setlease(struct file *filp, long arg,
				    struct file_lock **flp, void **priv)
{
	return -EINVAL;
}

static inline int vfs_setlease(struct file *filp, long arg,
			       struct file_lock **lease, void **priv)
{
	return -EINVAL;
}

static inline int lease_modify(struct file_lock *fl, int arg,
			       struct list_head *dispose)
{
	return -EINVAL;
}

struct files_struct;
static inline void show_fd_locks(struct seq_file *f,
			struct file *filp, struct files_struct *files) {}
#endif /* !CONFIG_FILE_LOCKING */

static inline struct inode *file_inode(const struct file *f)
{
	return f->f_inode;
}

static inline struct dentry *file_dentry(const struct file *file)
{
	return d_real(file->f_path.dentry, file_inode(file));
}

static inline int locks_lock_file_wait(struct file *filp, struct file_lock *fl)
{
	return locks_lock_inode_wait(locks_inode(filp), fl);
}

/* SMP safe fasync helpers: */
extern int fasync_helper(int, struct file *, int, struct fasync_struct **);
extern struct fasync_struct *fasync_insert_entry(int, struct file *, struct fasync_struct **, struct fasync_struct *);
extern int fasync_remove_entry(struct file *, struct fasync_struct **);
extern struct fasync_struct *fasync_alloc(void);
extern void fasync_free(struct fasync_struct *);

/* can be called from interrupts */
extern void kill_fasync(struct fasync_struct **, int, int);

extern void __f_setown(struct file *filp, struct pid *, enum pid_type, int force);
extern int f_setown(struct file *filp, unsigned long arg, int force);
extern void f_delown(struct file *filp);
extern pid_t f_getown(struct file *filp);
extern int send_sigurg(struct fown_struct *fown);

static inline struct user_namespace *i_user_ns(const struct inode *inode)
{
	return inode->i_sb->s_user_ns;
}

/* Helper functions so that in most cases filesystems will
 * not need to deal directly with kuid_t and kgid_t and can
 * instead deal with the raw numeric values that are stored
 * in the filesystem.
 */
static inline uid_t i_uid_read(const struct inode *inode)
{
	return from_kuid(i_user_ns(inode), inode->i_uid);
}

static inline gid_t i_gid_read(const struct inode *inode)
{
	return from_kgid(i_user_ns(inode), inode->i_gid);
}

static inline void i_uid_write(struct inode *inode, uid_t uid)
{
	inode->i_uid = make_kuid(i_user_ns(inode), uid);
}

static inline void i_gid_write(struct inode *inode, gid_t gid)
{
	inode->i_gid = make_kgid(i_user_ns(inode), gid);
}

/**
 * i_uid_into_mnt - map an inode's i_uid down into a mnt_userns
 * @mnt_userns: user namespace of the mount the inode was found from
 * @inode: inode to map
 *
 * Return: the inode's i_uid mapped down according to @mnt_userns.
 * If the inode's i_uid has no mapping INVALID_UID is returned.
 */
static inline kuid_t i_uid_into_mnt(struct user_namespace *mnt_userns,
				    const struct inode *inode)
{
	return mapped_kuid_fs(mnt_userns, i_user_ns(inode), inode->i_uid);
}

/**
 * i_gid_into_mnt - map an inode's i_gid down into a mnt_userns
 * @mnt_userns: user namespace of the mount the inode was found from
 * @inode: inode to map
 *
 * Return: the inode's i_gid mapped down according to @mnt_userns.
 * If the inode's i_gid has no mapping INVALID_GID is returned.
 */
static inline kgid_t i_gid_into_mnt(struct user_namespace *mnt_userns,
				    const struct inode *inode)
{
	return mapped_kgid_fs(mnt_userns, i_user_ns(inode), inode->i_gid);
}

/**
 * inode_fsuid_set - initialize inode's i_uid field with callers fsuid
 * @inode: inode to initialize
 * @mnt_userns: user namespace of the mount the inode was found from
 *
 * Initialize the i_uid field of @inode. If the inode was found/created via
 * an idmapped mount map the caller's fsuid according to @mnt_users.
 */
static inline void inode_fsuid_set(struct inode *inode,
				   struct user_namespace *mnt_userns)
{
	inode->i_uid = mapped_fsuid(mnt_userns, i_user_ns(inode));
}

/**
 * inode_fsgid_set - initialize inode's i_gid field with callers fsgid
 * @inode: inode to initialize
 * @mnt_userns: user namespace of the mount the inode was found from
 *
 * Initialize the i_gid field of @inode. If the inode was found/created via
 * an idmapped mount map the caller's fsgid according to @mnt_users.
 */
static inline void inode_fsgid_set(struct inode *inode,
				   struct user_namespace *mnt_userns)
{
	inode->i_gid = mapped_fsgid(mnt_userns, i_user_ns(inode));
}

/**
 * fsuidgid_has_mapping() - check whether caller's fsuid/fsgid is mapped
 * @sb: the superblock we want a mapping in
 * @mnt_userns: user namespace of the relevant mount
 *
 * Check whether the caller's fsuid and fsgid have a valid mapping in the
 * s_user_ns of the superblock @sb. If the caller is on an idmapped mount map
 * the caller's fsuid and fsgid according to the @mnt_userns first.
 *
 * Return: true if fsuid and fsgid is mapped, false if not.
 */
static inline bool fsuidgid_has_mapping(struct super_block *sb,
					struct user_namespace *mnt_userns)
{
	struct user_namespace *fs_userns = sb->s_user_ns;
	kuid_t kuid;
	kgid_t kgid;

	kuid = mapped_fsuid(mnt_userns, fs_userns);
	if (!uid_valid(kuid))
		return false;
	kgid = mapped_fsgid(mnt_userns, fs_userns);
	if (!gid_valid(kgid))
		return false;
	return kuid_has_mapping(fs_userns, kuid) &&
	       kgid_has_mapping(fs_userns, kgid);
}

extern struct timespec64 current_time(struct inode *inode);

bool inode_owner_or_capable(struct user_namespace *mnt_userns,
			    const struct inode *inode);

/*
 * VFS helper functions..
 */
int vfs_create(struct user_namespace *, struct inode *,
	       struct dentry *, umode_t, bool);
int vfs_mkdir(struct user_namespace *, struct inode *,
	      struct dentry *, umode_t);
int vfs_mknod(struct user_namespace *, struct inode *, struct dentry *,
              umode_t, dev_t);
int vfs_symlink(struct user_namespace *, struct inode *,
		struct dentry *, const char *);
int vfs_link(struct dentry *, struct user_namespace *, struct inode *,
	     struct dentry *, struct inode **);
int vfs_rmdir(struct user_namespace *, struct inode *, struct dentry *);
int vfs_unlink(struct user_namespace *, struct inode *, struct dentry *,
	       struct inode **);

int vfs_rename(struct renamedata *);

static inline int vfs_whiteout(struct user_namespace *mnt_userns,
			       struct inode *dir, struct dentry *dentry)
{
	return vfs_mknod(mnt_userns, dir, dentry, S_IFCHR | WHITEOUT_MODE,
			 WHITEOUT_DEV);
}

struct dentry *vfs_tmpfile(struct user_namespace *mnt_userns,
			   struct dentry *dentry, umode_t mode, int open_flag);

int vfs_mkobj(struct dentry *, umode_t,
		int (*f)(struct dentry *, umode_t, void *),
		void *);

int vfs_fchown(struct file *file, uid_t user, gid_t group);
int vfs_fchmod(struct file *file, umode_t mode);
int vfs_utimes(const struct path *path, struct timespec64 *times);

extern long vfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#ifdef CONFIG_COMPAT
extern long compat_ptr_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg);
#else
#define compat_ptr_ioctl NULL
#endif

/*
 * VFS file helper functions.
 */
void inode_init_owner(struct user_namespace *mnt_userns, struct inode *inode,
		      const struct inode *dir, umode_t mode);
extern bool may_open_dev(const struct path *path);

static inline ssize_t call_read_iter(struct file *file, struct kiocb *kio,
				     struct iov_iter *iter)
{
	return file->f_op->read_iter(kio, iter);
}

static inline ssize_t call_write_iter(struct file *file, struct kiocb *kio,
				      struct iov_iter *iter)
{
	return file->f_op->write_iter(kio, iter);
}

static inline int call_mmap(struct file *file, struct vm_area_struct *vma)
{
	return file->f_op->mmap(file, vma);
}

extern ssize_t vfs_read(struct file *, char __user *, size_t, loff_t *);
extern ssize_t vfs_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t vfs_copy_file_range(struct file *, loff_t , struct file *,
				   loff_t, size_t, unsigned int);
extern ssize_t generic_copy_file_range(struct file *file_in, loff_t pos_in,
				       struct file *file_out, loff_t pos_out,
				       size_t len, unsigned int flags);
extern int generic_remap_file_range_prep(struct file *file_in, loff_t pos_in,
					 struct file *file_out, loff_t pos_out,
					 loff_t *count,
					 unsigned int remap_flags);
extern loff_t do_clone_file_range(struct file *file_in, loff_t pos_in,
				  struct file *file_out, loff_t pos_out,
				  loff_t len, unsigned int remap_flags);
extern loff_t vfs_clone_file_range(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   loff_t len, unsigned int remap_flags);
extern int vfs_dedupe_file_range(struct file *file,
				 struct file_dedupe_range *same);
extern loff_t vfs_dedupe_file_range_one(struct file *src_file, loff_t src_pos,
					struct file *dst_file, loff_t dst_pos,
					loff_t len, unsigned int remap_flags);


static inline bool HAS_UNMAPPED_ID(struct user_namespace *mnt_userns,
				   struct inode *inode)
{
	return !uid_valid(i_uid_into_mnt(mnt_userns, inode)) ||
	       !gid_valid(i_gid_into_mnt(mnt_userns, inode));
}

static inline enum rw_hint file_write_hint(struct file *file)
{
	if (file->f_write_hint != WRITE_LIFE_NOT_SET)
		return file->f_write_hint;

	return file_inode(file)->i_write_hint;
}

static inline int iocb_flags(struct file *file);

static inline u16 ki_hint_validate(enum rw_hint hint)
{
	typeof(((struct kiocb *)0)->ki_hint) max_hint = -1;

	if (hint <= max_hint)
		return hint;
	return 0;
}

extern void init_sync_kiocb(struct kiocb *kiocb, struct file *filp);
extern void kiocb_clone(struct kiocb *kiocb, struct kiocb *kiocb_src, struct file *filp);

extern void __mark_inode_dirty(struct inode *, int);
static inline void mark_inode_dirty(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY);
}

static inline void mark_inode_dirty_sync(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY_SYNC);
}

/*
 * Returns true if the given inode itself only has dirty timestamps (its pages
 * may still be dirty) and isn't currently being allocated or freed.
 * Filesystems should call this if when writing an inode when lazytime is
 * enabled, they want to opportunistically write the timestamps of other inodes
 * located very nearby on-disk, e.g. in the same inode block.  This returns true
 * if the given inode is in need of such an opportunistic update.  Requires
 * i_lock, or at least later re-checking under i_lock.
 */
static inline bool inode_is_dirtytime_only(struct inode *inode)
{
	return (inode->i_state & (I_DIRTY_TIME | I_NEW |
				  I_FREEING | I_WILL_FREE)) == I_DIRTY_TIME;
}

extern void inc_nlink(struct inode *inode);
extern void drop_nlink(struct inode *inode);
extern void clear_nlink(struct inode *inode);
extern void set_nlink(struct inode *inode, unsigned int nlink);

static inline void inode_inc_link_count(struct inode *inode)
{
	inc_nlink(inode);
	mark_inode_dirty(inode);
}

static inline void inode_dec_link_count(struct inode *inode)
{
	drop_nlink(inode);
	mark_inode_dirty(inode);
}

extern bool atime_needs_update(const struct path *, struct inode *);
extern void touch_atime(const struct path *);
int inode_update_time(struct inode *inode, struct timespec64 *time, int flags);

static inline void file_accessed(struct file *file)
{
	if (!(file->f_flags & O_NOATIME))
		touch_atime(&file->f_path);
}

extern int file_modified(struct file *file);

int sync_inode_metadata(struct inode *inode, int wait);

#define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)

extern struct dentry *mount_bdev(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data,
	int (*fill_super)(struct super_block *, void *, int));
extern struct dentry *mount_single(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int));
extern struct dentry *mount_nodev(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int));
extern struct dentry *mount_subtree(struct vfsmount *mnt, const char *path);
void generic_shutdown_super(struct super_block *sb);
void kill_block_super(struct super_block *sb);
void kill_anon_super(struct super_block *sb);
void kill_litter_super(struct super_block *sb);
void deactivate_super(struct super_block *sb);
void deactivate_locked_super(struct super_block *sb);
int set_anon_super(struct super_block *s, void *data);
int set_anon_super_fc(struct super_block *s, struct fs_context *fc);
int get_anon_bdev(dev_t *);
void free_anon_bdev(dev_t);
struct super_block *sget_fc(struct fs_context *fc,
			    int (*test)(struct super_block *, struct fs_context *),
			    int (*set)(struct super_block *, struct fs_context *));
struct super_block *sget(struct file_system_type *type,
			int (*test)(struct super_block *,void *),
			int (*set)(struct super_block *,void *),
			int flags, void *data);

/* Alas, no aliases. Too much hassle with bringing module.h everywhere */
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
/*
 * This one is to be used *ONLY* from ->open() instances.
 * fops must be non-NULL, pinned down *and* module dependencies
 * should be sufficient to pin the caller down as well.
 */
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)

extern int register_filesystem(struct file_system_type *);
extern int unregister_filesystem(struct file_system_type *);
extern struct vfsmount *kern_mount(struct file_system_type *);
extern void kern_unmount(struct vfsmount *mnt);
extern int may_umount_tree(struct vfsmount *);
extern int may_umount(struct vfsmount *);
extern long do_mount(const char *, const char __user *,
		     const char *, unsigned long, void *);
extern struct vfsmount *collect_mounts(const struct path *);
extern void drop_collected_mounts(struct vfsmount *);
extern int iterate_mounts(int (*)(struct vfsmount *, void *), void *,
			  struct vfsmount *);
extern int vfs_statfs(const struct path *, struct kstatfs *);
extern int user_statfs(const char __user *, struct kstatfs *);
extern int fd_statfs(int, struct kstatfs *);
extern int freeze_super(struct super_block *super);
extern int thaw_super(struct super_block *super);
extern bool our_mnt(struct vfsmount *mnt);
extern __printf(2, 3)
int super_setup_bdi_name(struct super_block *sb, char *fmt, ...);
extern int super_setup_bdi(struct super_block *sb);

extern int current_umask(void);

extern void ihold(struct inode * inode);
extern void iput(struct inode *);
extern int generic_update_time(struct inode *, struct timespec64 *, int);

/* /sys/fs */
extern struct kobject *fs_kobj;

#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)

#ifdef CONFIG_FILE_LOCKING
static inline int break_lease(struct inode *inode, unsigned int mode)
{
	/*
	 * Since this check is lockless, we must ensure that any refcounts
	 * taken are done before checking i_flctx->flc_lease. Otherwise, we
	 * could end up racing with tasks trying to set a new lease on this
	 * file.
	 */
	smp_mb();
	if (inode->i_flctx && !list_empty_careful(&inode->i_flctx->flc_lease))
		return __break_lease(inode, mode, FL_LEASE);
	return 0;
}

static inline int break_deleg(struct inode *inode, unsigned int mode)
{
	/*
	 * Since this check is lockless, we must ensure that any refcounts
	 * taken are done before checking i_flctx->flc_lease. Otherwise, we
	 * could end up racing with tasks trying to set a new lease on this
	 * file.
	 */
	smp_mb();
	if (inode->i_flctx && !list_empty_careful(&inode->i_flctx->flc_lease))
		return __break_lease(inode, mode, FL_DELEG);
	return 0;
}

static inline int try_break_deleg(struct inode *inode, struct inode **delegated_inode)
{
	int ret;

	ret = break_deleg(inode, O_WRONLY|O_NONBLOCK);
	if (ret == -EWOULDBLOCK && delegated_inode) {
		*delegated_inode = inode;
		ihold(inode);
	}
	return ret;
}

static inline int break_deleg_wait(struct inode **delegated_inode)
{
	int ret;

	ret = break_deleg(*delegated_inode, O_WRONLY);
	iput(*delegated_inode);
	*delegated_inode = NULL;
	return ret;
}

static inline int break_layout(struct inode *inode, bool wait)
{
	smp_mb();
	if (inode->i_flctx && !list_empty_careful(&inode->i_flctx->flc_lease))
		return __break_lease(inode,
				wait ? O_WRONLY : O_WRONLY | O_NONBLOCK,
				FL_LAYOUT);
	return 0;
}

#else /* !CONFIG_FILE_LOCKING */
static inline int break_lease(struct inode *inode, unsigned int mode)
{
	return 0;
}

static inline int break_deleg(struct inode *inode, unsigned int mode)
{
	return 0;
}

static inline int try_break_deleg(struct inode *inode, struct inode **delegated_inode)
{
	return 0;
}

static inline int break_deleg_wait(struct inode **delegated_inode)
{
	BUG();
	return 0;
}

static inline int break_layout(struct inode *inode, bool wait)
{
	return 0;
}

#endif /* CONFIG_FILE_LOCKING */

static_assert(offsetof(struct filename, iname) % sizeof(long) == 0);

static inline struct user_namespace *file_mnt_user_ns(struct file *file)
{
	return mnt_user_ns(file->f_path.mnt);
}

/**
 * is_idmapped_mnt - check whether a mount is mapped
 * @mnt: the mount to check
 *
 * If @mnt has an idmapping attached different from the
 * filesystem's idmapping then @mnt is mapped.
 *
 * Return: true if mount is mapped, false if not.
 */
static inline bool is_idmapped_mnt(const struct vfsmount *mnt)
{
	return mnt_user_ns(mnt) != mnt->mnt_sb->s_user_ns;
}

extern long vfs_truncate(const struct path *, loff_t);
int do_truncate(struct user_namespace *, struct dentry *, loff_t start,
		unsigned int time_attrs, struct file *filp);
extern int vfs_fallocate(struct file *file, int mode, loff_t offset,
			loff_t len);
extern long do_sys_open(int dfd, const char __user *filename, int flags,
			umode_t mode);
extern struct file *file_open_name(struct filename *, int, umode_t);
extern struct file *filp_open(const char *, int, umode_t);
extern struct file *file_open_root(const struct path *,
				   const char *, int, umode_t);
static inline struct file *file_open_root_mnt(struct vfsmount *mnt,
				   const char *name, int flags, umode_t mode)
{
	return file_open_root(&(struct path){.mnt = mnt, .dentry = mnt->mnt_root},
			      name, flags, mode);
}
extern struct file * dentry_open(const struct path *, int, const struct cred *);
extern struct file * open_with_fake_path(const struct path *, int,
					 struct inode*, const struct cred *);
static inline struct file *file_clone_open(struct file *file)
{
	return dentry_open(&file->f_path, file->f_flags, file->f_cred);
}
extern int filp_close(struct file *, fl_owner_t id);

extern struct filename *getname_flags(const char __user *, int, int *);
extern struct filename *getname_uflags(const char __user *, int);
extern struct filename *getname(const char __user *);
extern struct filename *getname_kernel(const char *);
extern void putname(struct filename *name);

extern int finish_open(struct file *file, struct dentry *dentry,
			int (*open)(struct inode *, struct file *));
extern int finish_no_open(struct file *file, struct dentry *dentry);

/* fs/dcache.c */
extern void vfs_caches_init_early(void);
extern void vfs_caches_init(void);

extern struct kmem_cache *names_cachep;

#define __getname()		kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __putname(name)		kmem_cache_free(names_cachep, (void *)(name))

extern struct super_block *blockdev_superblock;
static inline bool sb_is_blkdev_sb(struct super_block *sb)
{
	return IS_ENABLED(CONFIG_BLOCK) && sb == blockdev_superblock;
}

void emergency_thaw_all(void);
extern int sync_filesystem(struct super_block *);
extern const struct file_operations def_blk_fops;
extern const struct file_operations def_chr_fops;

extern int alloc_chrdev_region(dev_t *, unsigned, unsigned, const char *);
extern int register_chrdev_region(dev_t, unsigned, const char *);
extern int __register_chrdev(unsigned int major, unsigned int baseminor,
			     unsigned int count, const char *name,
			     const struct file_operations *fops);
extern void __unregister_chrdev(unsigned int major, unsigned int baseminor,
				unsigned int count, const char *name);
extern void unregister_chrdev_region(dev_t, unsigned);
extern void chrdev_show(struct seq_file *,off_t);

static inline int register_chrdev(unsigned int major, const char *name,
				  const struct file_operations *fops)
{
	return __register_chrdev(major, 0, 256, name, fops);
}

static inline void unregister_chrdev(unsigned int major, const char *name)
{
	__unregister_chrdev(major, 0, 256, name);
}

extern void init_special_inode(struct inode *, umode_t, dev_t);

/* Invalid inode operations -- fs/bad_inode.c */
extern void make_bad_inode(struct inode *);
extern bool is_bad_inode(struct inode *);

unsigned long invalidate_mapping_pages(struct address_space *mapping,
					pgoff_t start, pgoff_t end);

void invalidate_mapping_pagevec(struct address_space *mapping,
				pgoff_t start, pgoff_t end,
				unsigned long *nr_pagevec);

static inline void invalidate_remote_inode(struct inode *inode)
{
	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode))
		invalidate_mapping_pages(inode->i_mapping, 0, -1);
}
extern int invalidate_inode_pages2(struct address_space *mapping);
extern int invalidate_inode_pages2_range(struct address_space *mapping,
					 pgoff_t start, pgoff_t end);
extern int write_inode_now(struct inode *, int);
extern int filemap_fdatawrite(struct address_space *);
extern int filemap_flush(struct address_space *);
extern int filemap_fdatawait_keep_errors(struct address_space *mapping);
extern int filemap_fdatawait_range(struct address_space *, loff_t lstart,
				   loff_t lend);
extern int filemap_fdatawait_range_keep_errors(struct address_space *mapping,
		loff_t start_byte, loff_t end_byte);

static inline int filemap_fdatawait(struct address_space *mapping)
{
	return filemap_fdatawait_range(mapping, 0, LLONG_MAX);
}

extern bool filemap_range_has_page(struct address_space *, loff_t lstart,
				  loff_t lend);
extern int filemap_write_and_wait_range(struct address_space *mapping,
				        loff_t lstart, loff_t lend);
extern int __filemap_fdatawrite_range(struct address_space *mapping,
				loff_t start, loff_t end, int sync_mode);
extern int filemap_fdatawrite_range(struct address_space *mapping,
				loff_t start, loff_t end);
extern int filemap_check_errors(struct address_space *mapping);
extern void __filemap_set_wb_err(struct address_space *mapping, int err);
int filemap_fdatawrite_wbc(struct address_space *mapping,
			   struct writeback_control *wbc);

static inline int filemap_write_and_wait(struct address_space *mapping)
{
	return filemap_write_and_wait_range(mapping, 0, LLONG_MAX);
}

extern int __must_check file_fdatawait_range(struct file *file, loff_t lstart,
						loff_t lend);
extern int __must_check file_check_and_advance_wb_err(struct file *file);
extern int __must_check file_write_and_wait_range(struct file *file,
						loff_t start, loff_t end);

static inline int file_write_and_wait(struct file *file)
{
	return file_write_and_wait_range(file, 0, LLONG_MAX);
}

/**
 * filemap_set_wb_err - set a writeback error on an address_space
 * @mapping: mapping in which to set writeback error
 * @err: error to be set in mapping
 *
 * When writeback fails in some way, we must record that error so that
 * userspace can be informed when fsync and the like are called.  We endeavor
 * to report errors on any file that was open at the time of the error.  Some
 * internal callers also need to know when writeback errors have occurred.
 *
 * When a writeback error occurs, most filesystems will want to call
 * filemap_set_wb_err to record the error in the mapping so that it will be
 * automatically reported whenever fsync is called on the file.
 */
static inline void filemap_set_wb_err(struct address_space *mapping, int err)
{
	/* Fastpath for common case of no error */
	if (unlikely(err))
		__filemap_set_wb_err(mapping, err);
}

/**
 * filemap_check_wb_err - has an error occurred since the mark was sampled?
 * @mapping: mapping to check for writeback errors
 * @since: previously-sampled errseq_t
 *
 * Grab the errseq_t value from the mapping, and see if it has changed "since"
 * the given value was sampled.
 *
 * If it has then report the latest error set, otherwise return 0.
 */
static inline int filemap_check_wb_err(struct address_space *mapping,
					errseq_t since)
{
	return errseq_check(&mapping->wb_err, since);
}

/**
 * filemap_sample_wb_err - sample the current errseq_t to test for later errors
 * @mapping: mapping to be sampled
 *
 * Writeback errors are always reported relative to a particular sample point
 * in the past. This function provides those sample points.
 */
static inline errseq_t filemap_sample_wb_err(struct address_space *mapping)
{
	return errseq_sample(&mapping->wb_err);
}

/**
 * file_sample_sb_err - sample the current errseq_t to test for later errors
 * @file: file pointer to be sampled
 *
 * Grab the most current superblock-level errseq_t value for the given
 * struct file.
 */
static inline errseq_t file_sample_sb_err(struct file *file)
{
	return errseq_sample(&file->f_path.dentry->d_sb->s_wb_err);
}

extern int vfs_fsync_range(struct file *file, loff_t start, loff_t end,
			   int datasync);
extern int vfs_fsync(struct file *file, int datasync);

extern int sync_file_range(struct file *file, loff_t offset, loff_t nbytes,
				unsigned int flags);

/*
 * Sync the bytes written if this was a synchronous write.  Expect ki_pos
 * to already be updated for the write, and will return either the amount
 * of bytes passed in, or an error if syncing the file failed.
 */
static inline ssize_t generic_write_sync(struct kiocb *iocb, ssize_t count)
{
	if (iocb->ki_flags & IOCB_DSYNC) {
		int ret = vfs_fsync_range(iocb->ki_filp,
				iocb->ki_pos - count, iocb->ki_pos - 1,
				(iocb->ki_flags & IOCB_SYNC) ? 0 : 1);
		if (ret)
			return ret;
	}

	return count;
}

extern void emergency_sync(void);
extern void emergency_remount(void);

#ifdef CONFIG_BLOCK
extern int bmap(struct inode *inode, sector_t *block);
#else
static inline int bmap(struct inode *inode,  sector_t *block)
{
	return -EINVAL;
}
#endif

int notify_change(struct user_namespace *, struct dentry *,
		  struct iattr *, struct inode **);
int inode_permission(struct user_namespace *, struct inode *, int);
int generic_permission(struct user_namespace *, struct inode *, int);
static inline int file_permission(struct file *file, int mask)
{
	return inode_permission(file_mnt_user_ns(file),
				file_inode(file), mask);
}
static inline int path_permission(const struct path *path, int mask)
{
	return inode_permission(mnt_user_ns(path->mnt),
				d_inode(path->dentry), mask);
}
int __check_sticky(struct user_namespace *mnt_userns, struct inode *dir,
		   struct inode *inode);

static inline bool execute_ok(struct inode *inode)
{
	return (inode->i_mode & S_IXUGO) || S_ISDIR(inode->i_mode);
}

static inline bool inode_wrong_type(const struct inode *inode, umode_t mode)
{
	return (inode->i_mode ^ mode) & S_IFMT;
}

/*
 * This is used for regular files where some users -- especially the
 * currently executed binary in a process, previously handled via
 * VM_DENYWRITE -- cannot handle concurrent write (and maybe mmap
 * read-write shared) accesses.
 *
 * get_write_access() gets write permission for a file.
 * put_write_access() releases this write permission.
 * deny_write_access() denies write access to a file.
 * allow_write_access() re-enables write access to a file.
 *
 * The i_writecount field of an inode can have the following values:
 * 0: no write access, no denied write access
 * < 0: (-i_writecount) users that denied write access to the file.
 * > 0: (i_writecount) users that have write access to the file.
 *
 * Normally we operate on that counter with atomic_{inc,dec} and it's safe
 * except for the cases where we don't hold i_writecount yet. Then we need to
 * use {get,deny}_write_access() - these functions check the sign and refuse
 * to do the change if sign is wrong.
 */
static inline int get_write_access(struct inode *inode)
{
	return atomic_inc_unless_negative(&inode->i_writecount) ? 0 : -ETXTBSY;
}
static inline int deny_write_access(struct file *file)
{
	struct inode *inode = file_inode(file);
	return atomic_dec_unless_positive(&inode->i_writecount) ? 0 : -ETXTBSY;
}
static inline void put_write_access(struct inode * inode)
{
	atomic_dec(&inode->i_writecount);
}
static inline void allow_write_access(struct file *file)
{
	if (file)
		atomic_inc(&file_inode(file)->i_writecount);
}
static inline bool inode_is_open_for_write(const struct inode *inode)
{
	return atomic_read(&inode->i_writecount) > 0;
}

#if defined(CONFIG_IMA) || defined(CONFIG_FILE_LOCKING)
static inline void i_readcount_dec(struct inode *inode)
{
	BUG_ON(!atomic_read(&inode->i_readcount));
	atomic_dec(&inode->i_readcount);
}
static inline void i_readcount_inc(struct inode *inode)
{
	atomic_inc(&inode->i_readcount);
}
#else
static inline void i_readcount_dec(struct inode *inode)
{
	return;
}
static inline void i_readcount_inc(struct inode *inode)
{
	return;
}
#endif
extern int do_pipe_flags(int *, int);

extern ssize_t kernel_read(struct file *, void *, size_t, loff_t *);
ssize_t __kernel_read(struct file *file, void *buf, size_t count, loff_t *pos);
extern ssize_t kernel_write(struct file *, const void *, size_t, loff_t *);
extern ssize_t __kernel_write(struct file *, const void *, size_t, loff_t *);
extern struct file * open_exec(const char *);
 
/* fs/dcache.c -- generic fs support functions */
extern bool is_subdir(struct dentry *, struct dentry *);
extern bool path_is_under(const struct path *, const struct path *);

extern char *file_path(struct file *, char *, int);

/* needed for stackable file system support */
extern loff_t default_llseek(struct file *file, loff_t offset, int whence);

extern loff_t vfs_llseek(struct file *file, loff_t offset, int whence);

extern int inode_init_always(struct super_block *, struct inode *);
extern void inode_init_once(struct inode *);
extern void address_space_init_once(struct address_space *mapping);
extern struct inode * igrab(struct inode *);
extern ino_t iunique(struct super_block *, ino_t);
extern int inode_needs_sync(struct inode *inode);
extern int generic_delete_inode(struct inode *inode);
static inline int generic_drop_inode(struct inode *inode)
{
	return !inode->i_nlink || inode_unhashed(inode);
}
extern void d_mark_dontcache(struct inode *inode);

extern struct inode *ilookup5_nowait(struct super_block *sb,
		unsigned long hashval, int (*test)(struct inode *, void *),
		void *data);
extern struct inode *ilookup5(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data);
extern struct inode *ilookup(struct super_block *sb, unsigned long ino);

extern struct inode *inode_insert5(struct inode *inode, unsigned long hashval,
		int (*test)(struct inode *, void *),
		int (*set)(struct inode *, void *),
		void *data);
extern struct inode * iget5_locked(struct super_block *, unsigned long, int (*test)(struct inode *, void *), int (*set)(struct inode *, void *), void *);
extern struct inode * iget_locked(struct super_block *, unsigned long);
extern struct inode *find_inode_nowait(struct super_block *,
				       unsigned long,
				       int (*match)(struct inode *,
						    unsigned long, void *),
				       void *data);
extern struct inode *find_inode_rcu(struct super_block *, unsigned long,
				    int (*)(struct inode *, void *), void *);
extern struct inode *find_inode_by_ino_rcu(struct super_block *, unsigned long);
extern int insert_inode_locked4(struct inode *, unsigned long, int (*test)(struct inode *, void *), void *);
extern int insert_inode_locked(struct inode *);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
extern void lockdep_annotate_inode_mutex_key(struct inode *inode);
#else
static inline void lockdep_annotate_inode_mutex_key(struct inode *inode) { };
#endif
extern void unlock_new_inode(struct inode *);
extern void discard_new_inode(struct inode *);
extern unsigned int get_next_ino(void);
extern void evict_inodes(struct super_block *sb);
void dump_mapping(const struct address_space *);

/*
 * Userspace may rely on the the inode number being non-zero. For example, glibc
 * simply ignores files with zero i_ino in unlink() and other places.
 *
 * As an additional complication, if userspace was compiled with
 * _FILE_OFFSET_BITS=32 on a 64-bit kernel we'll only end up reading out the
 * lower 32 bits, so we need to check that those aren't zero explicitly. With
 * _FILE_OFFSET_BITS=64, this may cause some harmless false-negatives, but
 * better safe than sorry.
 */
static inline bool is_zero_ino(ino_t ino)
{
	return (u32)ino == 0;
}

extern void __iget(struct inode * inode);
extern void iget_failed(struct inode *);
extern void clear_inode(struct inode *);
extern void __destroy_inode(struct inode *);
extern struct inode *new_inode_pseudo(struct super_block *sb);
extern struct inode *new_inode(struct super_block *sb);
extern void free_inode_nonrcu(struct inode *inode);
extern int should_remove_suid(struct dentry *);
extern int file_remove_privs(struct file *);

extern void __insert_inode_hash(struct inode *, unsigned long hashval);
static inline void insert_inode_hash(struct inode *inode)
{
	__insert_inode_hash(inode, inode->i_ino);
}

extern void __remove_inode_hash(struct inode *);
static inline void remove_inode_hash(struct inode *inode)
{
	if (!inode_unhashed(inode) && !hlist_fake(&inode->i_hash))
		__remove_inode_hash(inode);
}

extern void inode_sb_list_add(struct inode *inode);
extern void inode_add_lru(struct inode *inode);

extern int sb_set_blocksize(struct super_block *, int);
extern int sb_min_blocksize(struct super_block *, int);

extern int generic_file_mmap(struct file *, struct vm_area_struct *);
extern int generic_file_readonly_mmap(struct file *, struct vm_area_struct *);
extern ssize_t generic_write_checks(struct kiocb *, struct iov_iter *);
extern int generic_write_check_limits(struct file *file, loff_t pos,
		loff_t *count);
extern int generic_file_rw_checks(struct file *file_in, struct file *file_out);
ssize_t filemap_read(struct kiocb *iocb, struct iov_iter *to,
		ssize_t already_read);
extern ssize_t generic_file_read_iter(struct kiocb *, struct iov_iter *);
extern ssize_t __generic_file_write_iter(struct kiocb *, struct iov_iter *);
extern ssize_t generic_file_write_iter(struct kiocb *, struct iov_iter *);
extern ssize_t generic_file_direct_write(struct kiocb *, struct iov_iter *);
extern ssize_t generic_perform_write(struct file *, struct iov_iter *, loff_t);

ssize_t vfs_iter_read(struct file *file, struct iov_iter *iter, loff_t *ppos,
		rwf_t flags);
ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos,
		rwf_t flags);
ssize_t vfs_iocb_iter_read(struct file *file, struct kiocb *iocb,
			   struct iov_iter *iter);
ssize_t vfs_iocb_iter_write(struct file *file, struct kiocb *iocb,
			    struct iov_iter *iter);

/* fs/splice.c */
extern ssize_t generic_file_splice_read(struct file *, loff_t *,
		struct pipe_inode_info *, size_t, unsigned int);
extern ssize_t iter_file_splice_write(struct pipe_inode_info *,
		struct file *, loff_t *, size_t, unsigned int);
extern ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe,
		struct file *out, loff_t *, size_t len, unsigned int flags);
extern long do_splice_direct(struct file *in, loff_t *ppos, struct file *out,
		loff_t *opos, size_t len, unsigned int flags);


extern void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping);
extern loff_t noop_llseek(struct file *file, loff_t offset, int whence);
extern loff_t no_llseek(struct file *file, loff_t offset, int whence);
extern loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize);
extern loff_t generic_file_llseek(struct file *file, loff_t offset, int whence);
extern loff_t generic_file_llseek_size(struct file *file, loff_t offset,
		int whence, loff_t maxsize, loff_t eof);
extern loff_t fixed_size_llseek(struct file *file, loff_t offset,
		int whence, loff_t size);
extern loff_t no_seek_end_llseek_size(struct file *, loff_t, int, loff_t);
extern loff_t no_seek_end_llseek(struct file *, loff_t, int);
extern int generic_file_open(struct inode * inode, struct file * filp);
extern int nonseekable_open(struct inode * inode, struct file * filp);
extern int stream_open(struct inode * inode, struct file * filp);

extern void inode_set_flags(struct inode *inode, unsigned int flags,
			    unsigned int mask);

extern const struct file_operations generic_ro_fops;

#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))

extern int readlink_copy(char __user *, int, const char *);
extern int page_readlink(struct dentry *, char __user *, int);
extern const char *page_get_link(struct dentry *, struct inode *,
				 struct delayed_call *);
extern void page_put_link(void *);
extern int __page_symlink(struct inode *inode, const char *symname, int len,
		int nofs);
extern int page_symlink(struct inode *inode, const char *symname, int len);
extern const struct inode_operations page_symlink_inode_operations;
extern void kfree_link(void *);
void generic_fillattr(struct user_namespace *, struct inode *, struct kstat *);
void generic_fill_statx_attr(struct inode *inode, struct kstat *stat);
extern int vfs_getattr_nosec(const struct path *, struct kstat *, u32, unsigned int);
extern int vfs_getattr(const struct path *, struct kstat *, u32, unsigned int);
void __inode_add_bytes(struct inode *inode, loff_t bytes);
void inode_add_bytes(struct inode *inode, loff_t bytes);
void __inode_sub_bytes(struct inode *inode, loff_t bytes);
void inode_sub_bytes(struct inode *inode, loff_t bytes);
static inline loff_t __inode_get_bytes(struct inode *inode)
{
	return (((loff_t)inode->i_blocks) << 9) + inode->i_bytes;
}
loff_t inode_get_bytes(struct inode *inode);
void inode_set_bytes(struct inode *inode, loff_t bytes);
const char *simple_get_link(struct dentry *, struct inode *,
			    struct delayed_call *);
extern const struct inode_operations simple_symlink_inode_operations;

extern int iterate_dir(struct file *, struct dir_context *);

int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat,
		int flags);
int vfs_fstat(int fd, struct kstat *stat);

static inline int vfs_stat(const char __user *filename, struct kstat *stat)
{
	return vfs_fstatat(AT_FDCWD, filename, stat, 0);
}
static inline int vfs_lstat(const char __user *name, struct kstat *stat)
{
	return vfs_fstatat(AT_FDCWD, name, stat, AT_SYMLINK_NOFOLLOW);
}

extern const char *vfs_get_link(struct dentry *, struct delayed_call *);
extern int vfs_readlink(struct dentry *, char __user *, int);

extern struct file_system_type *get_filesystem(struct file_system_type *fs);
extern void put_filesystem(struct file_system_type *fs);
extern struct file_system_type *get_fs_type(const char *name);
extern struct super_block *get_super(struct block_device *);
extern struct super_block *get_active_super(struct block_device *bdev);
extern void drop_super(struct super_block *sb);
extern void drop_super_exclusive(struct super_block *sb);
extern void iterate_supers(void (*)(struct super_block *, void *), void *);
extern void iterate_supers_type(struct file_system_type *,
			        void (*)(struct super_block *, void *), void *);

extern int dcache_dir_open(struct inode *, struct file *);
extern int dcache_dir_close(struct inode *, struct file *);
extern loff_t dcache_dir_lseek(struct file *, loff_t, int);
extern int dcache_readdir(struct file *, struct dir_context *);
extern int simple_setattr(struct user_namespace *, struct dentry *,
			  struct iattr *);
extern int simple_getattr(struct user_namespace *, const struct path *,
			  struct kstat *, u32, unsigned int);
extern int simple_statfs(struct dentry *, struct kstatfs *);
extern int simple_open(struct inode *inode, struct file *file);
extern int simple_link(struct dentry *, struct inode *, struct dentry *);
extern int simple_unlink(struct inode *, struct dentry *);
extern int simple_rmdir(struct inode *, struct dentry *);
extern int simple_rename_exchange(struct inode *old_dir, struct dentry *old_dentry,
				  struct inode *new_dir, struct dentry *new_dentry);
extern int simple_rename(struct user_namespace *, struct inode *,
			 struct dentry *, struct inode *, struct dentry *,
			 unsigned int);
extern void simple_recursive_removal(struct dentry *,
                              void (*callback)(struct dentry *));
extern int noop_fsync(struct file *, loff_t, loff_t, int);
extern void noop_invalidatepage(struct page *page, unsigned int offset,
		unsigned int length);
extern ssize_t noop_direct_IO(struct kiocb *iocb, struct iov_iter *iter);
extern int simple_empty(struct dentry *);
extern int simple_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata);
extern const struct address_space_operations ram_aops;
extern int always_delete_dentry(const struct dentry *);
extern struct inode *alloc_anon_inode(struct super_block *);
extern int simple_nosetlease(struct file *, long, struct file_lock **, void **);
extern const struct dentry_operations simple_dentry_operations;

extern struct dentry *simple_lookup(struct inode *, struct dentry *, unsigned int flags);
extern ssize_t generic_read_dir(struct file *, char __user *, size_t, loff_t *);
extern const struct file_operations simple_dir_operations;
extern const struct inode_operations simple_dir_inode_operations;
extern void make_empty_dir_inode(struct inode *inode);
extern bool is_empty_dir_inode(struct inode *inode);
struct tree_descr { const char *name; const struct file_operations *ops; int mode; };
struct dentry *d_alloc_name(struct dentry *, const char *);
extern int simple_fill_super(struct super_block *, unsigned long,
			     const struct tree_descr *);
extern int simple_pin_fs(struct file_system_type *, struct vfsmount **mount, int *count);
extern void simple_release_fs(struct vfsmount **mount, int *count);

extern ssize_t simple_read_from_buffer(void __user *to, size_t count,
			loff_t *ppos, const void *from, size_t available);
extern ssize_t simple_write_to_buffer(void *to, size_t available, loff_t *ppos,
		const void __user *from, size_t count);

extern int __generic_file_fsync(struct file *, loff_t, loff_t, int);
extern int generic_file_fsync(struct file *, loff_t, loff_t, int);

extern int generic_check_addressable(unsigned, u64);

extern void generic_set_encrypted_ci_d_ops(struct dentry *dentry);

#ifdef CONFIG_MIGRATION
extern int buffer_migrate_page(struct address_space *,
				struct page *, struct page *,
				enum migrate_mode);
extern int buffer_migrate_page_norefs(struct address_space *,
				struct page *, struct page *,
				enum migrate_mode);
#else
#define buffer_migrate_page NULL
#define buffer_migrate_page_norefs NULL
#endif

int may_setattr(struct user_namespace *mnt_userns, struct inode *inode,
		unsigned int ia_valid);
int setattr_prepare(struct user_namespace *, struct dentry *, struct iattr *);
extern int inode_newsize_ok(const struct inode *, loff_t offset);
void setattr_copy(struct user_namespace *, struct inode *inode,
		  const struct iattr *attr);

extern int file_update_time(struct file *file);

static inline int iocb_flags(struct file *file)
{
	int res = 0;
	if (file->f_flags & O_APPEND)
		res |= IOCB_APPEND;
	if (file->f_flags & O_DIRECT)
		res |= IOCB_DIRECT;
	if ((file->f_flags & O_DSYNC) || IS_SYNC(file->f_mapping->host))
		res |= IOCB_DSYNC;
	if (file->f_flags & __O_SYNC)
		res |= IOCB_SYNC;
	return res;
}

static inline int kiocb_set_rw_flags(struct kiocb *ki, rwf_t flags)
{
	int kiocb_flags = 0;

	/* make sure there's no overlap between RWF and private IOCB flags */
	BUILD_BUG_ON((__force int) RWF_SUPPORTED & IOCB_EVENTFD);

	if (!flags)
		return 0;
	if (unlikely(flags & ~RWF_SUPPORTED))
		return -EOPNOTSUPP;

	if (flags & RWF_NOWAIT) {
		if (!(ki->ki_filp->f_mode & FMODE_NOWAIT))
			return -EOPNOTSUPP;
		kiocb_flags |= IOCB_NOIO;
	}
	kiocb_flags |= (__force int) (flags & RWF_SUPPORTED);
	if (flags & RWF_SYNC)
		kiocb_flags |= IOCB_DSYNC;

	ki->ki_flags |= kiocb_flags;
	return 0;
}

extern ino_t parent_ino(struct dentry *dentry);

/* Transaction based IO helpers */

/*
 * An argresp is stored in an allocated page and holds the
 * size of the argument or response, along with its content
 */
struct simple_transaction_argresp {
	ssize_t size;
	char data[];
};

#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))

char *simple_transaction_get(struct file *file, const char __user *buf,
				size_t size);
ssize_t simple_transaction_read(struct file *file, char __user *buf,
				size_t size, loff_t *pos);
int simple_transaction_release(struct inode *inode, struct file *file);

void simple_transaction_set(struct file *file, size_t n);

/*
 * simple attribute files
 *
 * These attributes behave similar to those in sysfs:
 *
 * Writing to an attribute immediately sets a value, an open file can be
 * written to multiple times.
 *
 * Reading from an attribute creates a buffer from the value that might get
 * read with multiple read calls. When the attribute has been read
 * completely, no further read calls are possible until the file is opened
 * again.
 *
 * All attributes contain a text representation of a numeric value
 * that are accessed with the get() and set() functions.
 */
#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
	.llseek	 = generic_file_llseek,					\
}

static inline __printf(1, 2)
void __simple_attr_check_format(const char *fmt, ...)
{
	/* don't do anything, just let the compiler check the arguments; */
}

int simple_attr_open(struct inode *inode, struct file *file,
		     int (*get)(void *, u64 *), int (*set)(void *, u64),
		     const char *fmt);
int simple_attr_release(struct inode *inode, struct file *file);
ssize_t simple_attr_read(struct file *file, char __user *buf,
			 size_t len, loff_t *ppos);
ssize_t simple_attr_write(struct file *file, const char __user *buf,
			  size_t len, loff_t *ppos);

struct ctl_table;
int list_bdev_fs_names(char *buf, size_t size);

#define __FMODE_EXEC		((__force int) FMODE_EXEC)
#define __FMODE_NONOTIFY	((__force int) FMODE_NONOTIFY)

#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))

static inline bool is_sxid(umode_t mode)
{
	return (mode & S_ISUID) || ((mode & S_ISGID) && (mode & S_IXGRP));
}

static inline int check_sticky(struct user_namespace *mnt_userns,
			       struct inode *dir, struct inode *inode)
{
	if (!(dir->i_mode & S_ISVTX))
		return 0;

	return __check_sticky(mnt_userns, dir, inode);
}

static inline void inode_has_no_xattr(struct inode *inode)
{
	if (!is_sxid(inode->i_mode) && (inode->i_sb->s_flags & SB_NOSEC))
		inode->i_flags |= S_NOSEC;
}

static inline bool is_root_inode(struct inode *inode)
{
	return inode == inode->i_sb->s_root->d_inode;
}

static inline bool dir_relax(struct inode *inode)
{
	inode_unlock(inode);
	inode_lock(inode);
	return !IS_DEADDIR(inode);
}

static inline bool dir_relax_shared(struct inode *inode)
{
	inode_unlock_shared(inode);
	inode_lock_shared(inode);
	return !IS_DEADDIR(inode);
}

extern bool path_noexec(const struct path *path);
extern void inode_nohighmem(struct inode *inode);

/* mm/fadvise.c */
extern int vfs_fadvise(struct file *file, loff_t offset, loff_t len,
		       int advice);
extern int generic_fadvise(struct file *file, loff_t offset, loff_t len,
			   int advice);

#endif /* _LINUX_FS_API_H */
