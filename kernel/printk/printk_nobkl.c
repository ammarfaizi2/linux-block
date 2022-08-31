// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Linutronix GmbH, John Ogness
// Copyright (C) 2022 Intel, Thomas Gleixner

/*
 * Printk implementation for consoles which do not depend on the BKL style
 * console_lock() mechanism.
 *
 * Console is locked on a CPU when state::locked is set and state:cpu ==
 * current CPU. This is valid for the current execution context.
 *
 * Nesting execution contexts on the same CPU can carefully take over
 * if the driver allows reentrancy via state::unsafe = false. When the
 * interrupted context resumes it checks the state before entering
 * a unsafe region and aborts the operation it it detects the takeover.
 *
 * In case of panic or emergency the nesting context can take over the
 * console forcefully. The write callback is then invoked with the unsafe
 * flag set in the write context data which allows the driver side to avoid
 * locks and to evaluate the driver state so it can use an emergency path or
 * repair the state instead of blindly assuming that it works.
 *
 * If the interrupted context touches the assigned record buffer after
 * takeover that does not cause harm because at the same execution level
 * there is no concurrency on the same CPU. A threaded printer has always
 * its own record buffer so it can never interfere with any of the per CPU
 * record buffers.
 *
 * A concurrent writer on a different CPU can request to take over the
 * console by:
 *
 *	1) Carefully writing the desired state into state[HANDOVER]
 *	   if there is no same or higher priority request pending
 *	   This locks state[HANDOVER] except for higher priority
 *	   waiters.
 *
 *	2) Setting state[REAL].req_prio unless a higher priority
 *	   waiter won the race.
 *
 *	3) Carefully spin on state[REAL] until that is locked with the
 *	   expected state. When the state is not the expected one then it
 *	   has to verify that state[HANDOVER] is still the same and that
 *	   state[REAL] has not been taken over or marked dead.
 *
 *      The unlocker hands over to state[HANDOVER], but only if state[REAL]
 *	matches.
 *
 * In case that the owner does not react on the request and does not make
 * observable progress, the caller can decide to do a hostile take over.
 */

#ifdef CONFIG_PRINTK

#define copy_full_state(_dst, _src)	do { _dst = _src; } while(0)
#define copy_bit_state(_dst, _src)	do { _dst.bits = _src.bits; } while(0)

#ifdef CONFIG_64BIT
#define copy_seq_state64(_dst, _src)	do { _dst.seq = _src.seq; } while(0)
#else
#define copy_seq_state64(_dst, _src)	do { } while(0)
#endif

enum state_selector {
	STATE_REAL,
	STATE_HANDOVER,
};

/**
 * cons_state_set - Helper function to set the console state
 * @con:	Console to update
 * @which:	Selects real state or handover state
 * @new:	The new state to write
 *
 * Only to be used when the console is not yet or not longer visible in the
 * system.
 */
static inline void cons_state_set(struct console *con, enum state_selector which,
				  struct cons_state *new)
{
	atomic_long_set(&ACCESS_PRIVATE(con, atomic_state[which]), new->atom);
}

/**
 * cons_state_read - Helper function to read the console state
 * @con:	Console to update
 * @which:	Selects real state or handover state
 * @state:	The state to store the result
 */
static inline void cons_state_read(struct console *con, enum state_selector which,
				   struct cons_state *state)
{
	state->atom = atomic_long_read(&ACCESS_PRIVATE(con, atomic_state[which]));
}

/**
 * cons_state_try_cmpxchg() - Helper function for atomic_long_try_cmpxchg() on console state
 * @con:	Console to update
 * @which:	Selects real state or handover state
 * @old:	Old state
 * @new:	New state
 *
 * Returns: True on success, false on fail
 */
static inline bool cons_state_try_cmpxchg(struct console *con,
					  enum state_selector which,
					  struct cons_state *old,
					  struct cons_state *new)
{
	return atomic_long_try_cmpxchg(&ACCESS_PRIVATE(con, atomic_state[which]),
				       &old->atom, new->atom);
}

/**
 * cons_state_mod_enabled - Helper function to en/disable a console
 * @con:	Console to modify
 */
static void cons_state_mod_enabled(struct console *con, bool enable)
{
	struct cons_state old, new;

	cons_state_read(con, STATE_REAL, &old);
	do {
		copy_full_state(new, old);
		new.enabled = enable;
	} while (!cons_state_try_cmpxchg(con, STATE_REAL, &old, &new));
}

/**
 * cons_state_disable - Helper function to disable a console
 * @con:	Console to disable
 */
static void cons_state_disable(struct console *con)
{
	cons_state_mod_enabled(con, false);
}

/**
 * cons_state_enable - Helper function to enable a console
 * @con:	Console to enable
 */
static void cons_state_enable(struct console *con)
{
	cons_state_mod_enabled(con, true);
}

/**
 * cons_nobkl_init - Initialize the NOBKL console state
 * @con:	Console to initialize
 */
static void cons_nobkl_init(struct console *con)
{
	struct cons_state state = {
		.alive = 1,
		.enabled = !!(con->flags & CON_ENABLED),
	};

	cons_state_set(con, STATE_REAL, &state);
}

/**
 * cons_nobkl_cleanup - Cleanup the NOBKL console state
 * @con:	Console to cleanup
 */
static void cons_nobkl_cleanup(struct console *con)
{
	struct cons_state state = { };

	cons_state_set(con, STATE_REAL, &state);
}

#else /* CONFIG_PRINTK */
static inline void cons_nobkl_init(struct console *con) { }
static inline void cons_nobkl_cleanup(struct console *con) { }
static inline void cons_state_disable(struct console *con) { }
static inline void cons_state_enable(struct console *con) { }
#endif /* !CONFIG_PRINTK */
