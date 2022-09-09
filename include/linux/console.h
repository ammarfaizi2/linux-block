/*
 *  linux/include/linux/console.h
 *
 *  Copyright (C) 1993        Hamish Macdonald
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Changed:
 * 10-Mar-94: Arno Griffioen: Conversion for vt100 emulator port from PC LINUX
 */

#ifndef _LINUX_CONSOLE_H_
#define _LINUX_CONSOLE_H_ 1

#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/irq_work.h>
#include <linux/rculist.h>
#include <linux/rcuwait.h>
#include <linux/types.h>

struct vc_data;
struct console_font_op;
struct console_font;
struct module;
struct tty_struct;
struct notifier_block;

enum con_scroll {
	SM_UP,
	SM_DOWN,
};

enum vc_intensity;

/**
 * struct consw - callbacks for consoles
 *
 * @con_scroll: move lines from @top to @bottom in direction @dir by @lines.
 *		Return true if no generic handling should be done.
 *		Invoked by csi_M and printing to the console.
 * @con_set_palette: sets the palette of the console to @table (optional)
 * @con_scrolldelta: the contents of the console should be scrolled by @lines.
 *		     Invoked by user. (optional)
 */
struct consw {
	struct module *owner;
	const char *(*con_startup)(void);
	void	(*con_init)(struct vc_data *vc, int init);
	void	(*con_deinit)(struct vc_data *vc);
	void	(*con_clear)(struct vc_data *vc, int sy, int sx, int height,
			int width);
	void	(*con_putc)(struct vc_data *vc, int c, int ypos, int xpos);
	void	(*con_putcs)(struct vc_data *vc, const unsigned short *s,
			int count, int ypos, int xpos);
	void	(*con_cursor)(struct vc_data *vc, int mode);
	bool	(*con_scroll)(struct vc_data *vc, unsigned int top,
			unsigned int bottom, enum con_scroll dir,
			unsigned int lines);
	int	(*con_switch)(struct vc_data *vc);
	int	(*con_blank)(struct vc_data *vc, int blank, int mode_switch);
	int	(*con_font_set)(struct vc_data *vc, struct console_font *font,
			unsigned int flags);
	int	(*con_font_get)(struct vc_data *vc, struct console_font *font);
	int	(*con_font_default)(struct vc_data *vc,
			struct console_font *font, char *name);
	int     (*con_resize)(struct vc_data *vc, unsigned int width,
			unsigned int height, unsigned int user);
	void	(*con_set_palette)(struct vc_data *vc,
			const unsigned char *table);
	void	(*con_scrolldelta)(struct vc_data *vc, int lines);
	int	(*con_set_origin)(struct vc_data *vc);
	void	(*con_save_screen)(struct vc_data *vc);
	u8	(*con_build_attr)(struct vc_data *vc, u8 color,
			enum vc_intensity intensity,
			bool blink, bool underline, bool reverse, bool italic);
	void	(*con_invert_region)(struct vc_data *vc, u16 *p, int count);
	u16    *(*con_screen_pos)(const struct vc_data *vc, int offset);
	unsigned long (*con_getxy)(struct vc_data *vc, unsigned long position,
			int *px, int *py);
	/*
	 * Flush the video console driver's scrollback buffer
	 */
	void	(*con_flush_scrollback)(struct vc_data *vc);
	/*
	 * Prepare the console for the debugger.  This includes, but is not
	 * limited to, unblanking the console, loading an appropriate
	 * palette, and allowing debugger generated output.
	 */
	int	(*con_debug_enter)(struct vc_data *vc);
	/*
	 * Restore the console to its pre-debug state as closely as possible.
	 */
	int	(*con_debug_leave)(struct vc_data *vc);
};

extern const struct consw *conswitchp;

extern const struct consw dummy_con;	/* dummy console buffer */
extern const struct consw vga_con;	/* VGA text console */
extern const struct consw newport_con;	/* SGI Newport console  */

int con_is_bound(const struct consw *csw);
int do_unregister_con_driver(const struct consw *csw);
int do_take_over_console(const struct consw *sw, int first, int last, int deflt);
void give_up_console(const struct consw *sw);
#ifdef CONFIG_HW_CONSOLE
int con_debug_enter(struct vc_data *vc);
int con_debug_leave(void);
#else
static inline int con_debug_enter(struct vc_data *vc)
{
	return 0;
}
static inline int con_debug_leave(void)
{
	return 0;
}
#endif

/* cursor */
#define CM_DRAW     (1)
#define CM_ERASE    (2)
#define CM_MOVE     (3)

#ifdef CONFIG_PRINTK
/* The maximum size of a formatted record (i.e. with prefix added per line) */
#define CONSOLE_LOG_MAX		1024

/* The maximum size for a dropped text message */
#define DROPPED_TEXT_MAX	64
#else
#define CONSOLE_LOG_MAX		0
#define DROPPED_TEXT_MAX	0
#endif

/* The maximum size of an formatted extended record */
#define CONSOLE_EXT_LOG_MAX	8192

/*
 * The interface for a console, or any other device that wants to capture
 * console messages (printer driver?)
 */

/**
 * cons_flags - General console flags
 * @CON_PRINTBUFFER:	Print the complete dmesg backlog on register/enable
 * @CON_CONSDEV:	Questionable historical leftover to denote which console
 *			driver is the preferred console which is defining what
 *			backs up /dev/console
 * @CON_ENABLED:	General enable state subject to note #1
 * @CON_BOOT:		Marks the console driver as early console driver which
 *			is used during boot before the real driver becomes available.
 *			It will be automatically unregistered unless the early console
 *			command line parameter for this console has the 'keep' option set.
 * @CON_ANYTIME:	A misnomed historical flag which tells the core code that the
 *			legacy @console::write callback can be invoked on a CPU which
 *			is marked OFFLINE. That's misleading as it suggests that there
 *			is no contextual limit for invoking the callback.
 * @CON_BRL:		Indicates a braille device which is exempt from receiving the
 *			printk spam for obvious reasons
 * @CON_EXTENDED:	The console supports the extended output format of /dev/kmesg
 *			which requires a larger output record buffer
 * @CON_NO_BKL:		Console can operate outside of the BKL style console_lock
 *			constraints.
 */
enum cons_flags {
	CON_PRINTBUFFER		= BIT(0),
	CON_CONSDEV		= BIT(1),
	CON_ENABLED		= BIT(2),
	CON_BOOT		= BIT(3),
	CON_ANYTIME		= BIT(4),
	CON_BRL			= BIT(5),
	CON_EXTENDED		= BIT(6),
	CON_NO_BKL		= BIT(7),
};

/**
 * struct cons_state - console state for NOBKL consoles
 * @atom:	Compound of the state fields for atomic operations
 * @seq:	Sequence for record tracking (64bit only)
 * @bits:	Compound of the state bits below
 *
 * @alive:	Console is alive. Required for teardown
 * @enabled:	Console is enabled. If 0, do not use
 * @locked:	Console is locked by a writer
 * @unsafe:	Console is busy in a non takeover region
 * @thread:	Current owner is the printk thread
 * @cur_prio:	The priority of the current output
 * @req_prio:	The priority of a handover request
 * @cpu:	The CPU on which the writer runs
 *
 * To be used for state read and preparation of atomic_long_cmpxchg()
 * operations.
 */
struct cons_state {
	union {
		unsigned long	atom;
		struct {
#ifdef CONFIG_64BIT
			u32	seq;
#endif
			union {
				u32	bits;
				struct {
					u32 alive	:  1;
					u32 enabled	:  1;
					u32 locked	:  1;
					u32 unsafe	:  1;
					u32 thread	:  1;
					u32 cur_prio	:  2;
					u32 req_prio	:  2;
					u32 cpu		: 18;
				};
			};
		};
	};
};

/**
 * struct cons_text_buf - console output text buffer
 * @ext_text:		Buffer for extended log format text
 * @text:		Buffer for ringbuffer text
 */
struct cons_text_buf {
	char	ext_text[CONSOLE_EXT_LOG_MAX];
	char	text[CONSOLE_LOG_MAX];
} __no_randomize_layout;

/**
 * struct cons_outbuf_desc - console output buffer descriptor
 * @txtbuf:		Pointer to buffer for storing the text
 * @outbuf:		Pointer to the position in @buffer for
 *			writing it out to the device
 * @seq:		The sequence requested
 * @dropped:		The dropped count
 * @len:		Message length
 * @extmsg:		Select extended format printing
 */
struct cons_outbuf_desc {
	struct cons_text_buf	*txtbuf;
	char			*outbuf;
	u64			seq;
	unsigned long		dropped;
	unsigned int		len;
	bool			extmsg;
};

/**
 * cons_prio - console writer priority for NOBKL consoles
 * @CONS_PRIO_NONE:		Unused
 * @CONS_PRIO_NORMAL:		Regular printk
 * @CONS_PRIO_EMERGENCY:	Emergency output (WARN/OOPS...)
 * @CONS_PRIO_PANIC:		Panic output
 * @CONS_PRIO_MAX:		The number of priority levels
 *
 * Emergency output can carefully takeover the console even without consent
 * of the owner, ideally only when @cons_state::unsafe is not set. Panic
 * output can ignore the unsafe flag as a last resort. If panic output is
 * active no takeover is possible until the panic output releases the
 * console.
 */
enum cons_prio {
	CONS_PRIO_NONE = 0,
	CONS_PRIO_NORMAL,
	CONS_PRIO_EMERGENCY,
	CONS_PRIO_PANIC,
	CONS_PRIO_MAX,
};

struct console;

/**
 * struct cons_context - Context for console acquire/release
 * @console:		The associated console
 * @state:		The state at acquire time
 * @old_state:		The old state when try_acquire() failed for analyis
 *			by the caller
 * @hov_state:		The handover state for spin and cleanup
 * @req_state:		The request state for spin and cleanup
 * @spinwait_max_us:	Limit for spinwait acquire
 * @oldseq:		The sequence number at acquire()
 * @newseq:		The sequence number for progress
 * @prio:		Priority of the context
 * @txtbuf:		Pointer to the text buffer for this context
 * @dropped:		Dropped counter for the current context
 * @thread:		The acquire is printk thread context
 * @hostile:		Hostile takeover requested. Cleared on normal
 *			acquire or friendly handover
 * @spinwait:		Spinwait on acquire if possible
 * @backlog:		Ringbuffer has pending records
 */
struct cons_context {
	struct console		*console;
	struct cons_state	state;
	struct cons_state	old_state;
	struct cons_state	hov_state;
	struct cons_state	req_state;
	u64			oldseq;
	u64			newseq;
	unsigned int		spinwait_max_us;
	enum cons_prio		prio;
	struct cons_text_buf	*txtbuf;
	unsigned long		dropped;
	unsigned int		thread		: 1;
	unsigned int		hostile		: 1;
	unsigned int		spinwait	: 1;
	unsigned int		backlog		: 1;
};

/**
 * struct cons_write_context - Context handed to the write callbacks
 * @ctxt:	The core console context
 * @outbuf:	Pointer to the text buffer for output
 * @len:	Length to write
 * @pos:	Current write position in @outbuf
 * @unsafe:	Invoked in unsafe state due to force takeover
 */
struct cons_write_context {
	struct cons_context __private	ctxt;
	char				*outbuf;
	unsigned int			len;
	unsigned int			pos;
	bool				unsafe;
};

#define CONS_MAX_NEST_LVL	8

/**
 * struct cons_context_data - console context data
 * @wctxt:		Write context per priority level
 * @txtbuf:		Buffer for storing the text
 *
 * Used for early boot embedded into struct console and for
 * per CPU data.
 *
 * The write contexts are allocated to avoid having them on stack, e.g. in
 * warn() or panic().
 */
struct cons_context_data {
	struct cons_write_context	wctxt[CONS_PRIO_MAX];
	struct cons_text_buf		txtbuf;
};

/**
 * struct console - The console descriptor structure
 * @name:		The name of the console driver
 * @write:		Write callback to output messages (Optional)
 * @read:		Read callback for console input (Optional)
 * @device:		The underlying TTY device driver (Optional)
 * @unblank:		Callback to unblank the console (Optional)
 * @setup:		Callback for initializing the console (Optional)
 * @exit:		Callback for teardown of the console (Optional)
 * @match:		Callback for matching a console (Optional)
 * @flags:		Console flags. See enum cons_flags
 * @index:		Console index, e.g. port number
 * @cflag:		TTY control mode flags
 * @ispeed:		TTY input speed
 * @ospeed:		TTY output speed
 * @seq:		Sequence number of the last ringbuffer record printed
 * @dropped:		Number of dropped ringbuffer records
 * @data:		Driver private data
 * @node:		hlist node for the console list
 *
 * @atomic_state:	State array for non-BKL consoles. Real and handover
 * @atomic_seq:		Sequence for record tracking (32bit only)
 * @kthread:		Pointer to kernel thread
 * @rcuwait:		RCU wait for the kernel thread
 * @irq_work:		IRQ work for thread wakeup
 * @kthread_running:	Indicator whether the kthread is running
 * @thread_txtbuf:	Pointer to thread private buffer
 * @write_atomic:	Write callback for atomic context
 * @write_thread:	Write callback for threaded printing
 * @pcpu_data:		Pointer to percpu context data
 * @ctxt_data:		Builtin context data for early boot and threaded printing
 */
struct console {
	char			name[16];
	void			(*write)(struct console *, const char *, unsigned);
	int			(*read)(struct console *, char *, unsigned);
	struct tty_driver	 *(*device)(struct console *, int *);
	void			(*unblank)(void);
	int			(*setup)(struct console *, char *);
	int			(*exit)(struct console *);
	int			(*match)(struct console *, char *name, int idx, char *options);
	short			flags;
	short			index;
	int			cflag;
	uint			ispeed;
	uint			ospeed;
	u64			seq;
	unsigned long		dropped;
	void			*data;
	struct hlist_node	node;

	/* NOBKL console specific members */
	atomic_long_t __private	atomic_state[2];
#ifndef CONFIG_64BIT
	atomic_t __private	atomic_seq;
#endif
	struct task_struct	*kthread;
	struct rcuwait		rcuwait;
	struct irq_work		irq_work;
	atomic_t		kthread_running;
	struct cons_text_buf	*thread_txtbuf;

	bool (*write_atomic)(struct console *con, struct cons_write_context *wctxt);
	bool (*write_thread)(struct console *con, struct cons_write_context *wctxt);

	struct cons_context_data __percpu	*pcpu_data;
	struct cons_context_data		ctxt_data;
};

#ifdef CONFIG_LOCKDEP
extern void lockdep_assert_console_lock_held(void);
extern void lockdep_assert_console_list_lock_held(void);
extern bool console_srcu_read_lock_is_held(void);
#else
static inline void lockdep_assert_console_lock_held(void) { }
static inline void lockdep_assert_console_list_lock_held(void) { }
#endif

extern struct hlist_head console_list;

extern void console_list_lock(void) __acquires(console_mutex);
extern void console_list_unlock(void) __releases(console_mutex);

/**
 * for_each_console_srcu() - Iterator over registered consoles
 * @con:	struct console pointer used as loop cursor
 *
 * Requires console_srcu_read_lock to be held. Can be invoked from
 * any context.
 */
#define for_each_console_srcu(con)					\
	hlist_for_each_entry_srcu(con, &console_list, node,		\
				  console_srcu_read_lock_is_held())

/**
 * for_each_registered_console() - Iterator over registered consoles
 * @con:	struct console pointer used as loop cursor
 *
 * Requires console_list_lock to be held. Can only be invoked from
 * preemptible context.
 */
#define for_each_registered_console(con)				\
	lockdep_assert_console_list_lock_held();			\
	hlist_for_each_entry(con, &console_list, node)

/**
 * for_each_console() - Iterator over registered consoles
 * @con:	struct console pointer used as loop cursor
 *
 * Requires console_lock to be held which guarantees that the
 * list is immutable.
 */
#define for_each_console(con)						\
	lockdep_assert_console_lock_held();				\
	hlist_for_each_entry(con, &console_list, node)

/**
 * for_each_console_kgdb() - Iterator over registered consoles for KGDB
 * @con:	struct console pointer used as loop cursor
 *
 * Has no serialization requirements and KGDB pretends that this is safe.
 * Don't use outside of the KGDB fairy tale land!
 */
#define for_each_console_kgdb(con)					\
	hlist_for_each_entry(con, &console_list, node)

extern bool console_can_proceed(struct cons_write_context *wctxt);
extern bool console_enter_unsafe(struct cons_write_context *wctxt);
extern bool console_exit_unsafe(struct cons_write_context *wctxt);

extern enum cons_prio cons_atomic_enter(enum cons_prio prio);
extern void cons_atomic_exit(enum cons_prio prio, enum cons_prio prev_prio);

extern int console_set_on_cmdline;
extern struct console *early_console;

enum con_flush_mode {
	CONSOLE_FLUSH_PENDING,
	CONSOLE_REPLAY_ALL,
};

extern int add_preferred_console(char *name, int idx, char *options);
extern void register_console(struct console *);
extern int unregister_console(struct console *);
extern void console_lock(void);
extern int console_trylock(void);
extern void console_unlock(void);
extern void console_conditional_schedule(void);
extern void console_unblank(void);
extern void console_flush_on_panic(enum con_flush_mode mode);
extern struct tty_driver *console_device(int *);
extern void console_stop(struct console *);
extern void console_start(struct console *);
extern int is_console_locked(void);
extern int braille_register_console(struct console *, int index,
		char *console_options, char *braille_options);
extern int braille_unregister_console(struct console *);
#ifdef CONFIG_TTY
extern void console_sysfs_notify(void);
#else
static inline void console_sysfs_notify(void)
{ }
#endif
extern bool console_suspend_enabled;

/* Suspend and resume console messages over PM events */
extern void suspend_console(void);
extern void resume_console(void);

int mda_console_init(void);

void vcs_make_sysfs(int index);
void vcs_remove_sysfs(int index);

/* Some debug stub to catch some of the obvious races in the VT code */
#define WARN_CONSOLE_UNLOCKED()						\
	WARN_ON(!atomic_read(&ignore_console_lock_warning) &&		\
		!is_console_locked() && !oops_in_progress)
/*
 * Increment ignore_console_lock_warning if you need to quiet
 * WARN_CONSOLE_UNLOCKED() for debugging purposes.
 */
extern atomic_t ignore_console_lock_warning;

/* VESA Blanking Levels */
#define VESA_NO_BLANKING        0
#define VESA_VSYNC_SUSPEND      1
#define VESA_HSYNC_SUSPEND      2
#define VESA_POWERDOWN          3

extern void console_init(void);

/* For deferred console takeover */
void dummycon_register_output_notifier(struct notifier_block *nb);
void dummycon_unregister_output_notifier(struct notifier_block *nb);

#endif /* _LINUX_CONSOLE_H */
