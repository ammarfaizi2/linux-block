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
 * cons_state_ok - Check whether state is ok for usage
 * @state:	The state to check
 *
 * Returns: True if usable, false otherwise.
 */
static inline bool cons_state_ok(struct cons_state state)
{
	return state.alive && state.enabled;
}

/**
 * cons_state_full_match - Check whether the full state matches
 * @cur:	The state to check
 * @prev:	The previous state
 *
 * Returns: True if matching, false otherwise.
 *
 * Check the full state including state::seq on 64bit. For take over
 * detection.
 */
static inline bool cons_state_full_match(struct cons_state cur,
					 struct cons_state prev)
{
	/*
	 * req_prio can be set by a concurrent writer for friendly
	 * handover. Ignore it in the comparison.
	 */
	cur.req_prio = prev.req_prio;
	return cur.atom == prev.atom;
}

/**
 * cons_state_bits_match - Check for matching state bits
 * @cur:	The state to check
 * @prev:	The previous state
 *
 * Returns: True if state matches, false otherwise.
 *
 * Contrary to cons_state_full_match this checks only the bits and ignores
 * a sequence change on 64bits. On 32bit the two functions are identical.
 */
static inline bool cons_state_bits_match(struct cons_state cur,
					  struct cons_state prev)
{
	/*
	 * req_prio can be set by a concurrent writer for friendly
	 * handover. Ignore it in the comparison.
	 */
	cur.req_prio = prev.req_prio;
	return cur.bits == prev.bits;
}

/**
 * cons_check_panic - Check whether a remote CPU paniced
 */
static inline bool cons_check_panic(void)
{
	unsigned int pcpu = atomic_read(&panic_cpu);

	return pcpu != PANIC_CPU_INVALID && pcpu != smp_processor_id();
}

/**
 * cons_cleanup_handover - Cleanup a handover request
 * @ctxt:	Pointer to acquire context
 *
 * @ctxt->hov_state contains the state to clean up
 */
static void cons_cleanup_handover(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state new;

	/*
	 * No loop required. Either hov_state is still the same or
	 * not.
	 */
	new.atom = 0;
	cons_state_try_cmpxchg(con, STATE_HANDOVER, &ctxt->hov_state, &new);
}

/**
 * cons_setup_handover - Setup a handover request
 * @ctxt:	Pointer to acquire context
 *
 * On success @ctxt->hov_state contains the requested handover state
 */
static bool cons_setup_handover(struct cons_context *ctxt)
{
	unsigned int cpu = smp_processor_id();
	struct console *con = ctxt->console;
	struct cons_state old;
	struct cons_state hstate = {
		.alive		= 1,
		.enabled	= 1,
		.locked		= 1,
		.cur_prio	= ctxt->prio,
		.cpu		= cpu,
	};

	/*
	 * Try to store hstate in @con->atomic_state[HANDOVER]. This might
	 * race with a higher priority waiter.
	 */
	cons_state_read(con, STATE_HANDOVER, &old);
	do {
		if (cons_check_panic())
			return false;

		/* Same or higher priority waiter exists? */
		if (old.cur_prio >= ctxt->prio)
			return false;

	} while (!cons_state_try_cmpxchg(con, STATE_HANDOVER, &old, &hstate));

	copy_full_state(ctxt->hov_state, hstate);
	return true;
}

/**
 * cons_setup_request - Setup a handover request in state[REAL]
 * @ctxt:	Pointer to acquire context
 * @old:	The state which was used to make the decision to spin wait
 *
 * @ctxt->hov_state contains the handover state which was set in
 * state[HANDOVER]
 */
static bool cons_setup_request(struct cons_context *ctxt, struct cons_state old)
{
	struct console *con = ctxt->console;
	struct cons_state cur, new;

	/* Now set the request in state[REAL] */
	cons_state_read(con, STATE_REAL, &cur);
	do {
		if (cons_check_panic())
			goto cleanup;

		/* Bit state changed vs. the decision to spinwait? */
		if (!cons_state_bits_match(cur, old))
			goto cleanup;

		/* Setup a request for handover. */
		copy_full_state(new, cur);
		new.req_prio = ctxt->prio;
	} while (!cons_state_try_cmpxchg(con, STATE_REAL, &cur, &new));

	/* Safe that state for comparision in spinwait */
	copy_bit_state(ctxt->req_state, new);
	return true;

cleanup:
	cons_cleanup_handover(ctxt);
	return false;
}

/**
 * cons_try_acquire_spin - Complete the spinwait attempt
 * @ctxt:	Pointer to an aquire context which contains
 *		all information about the acquire mode
 *
 * @ctxt->hov_state contains the handover state which was set in
 * state[HANDOVER]
 * @ctxt->req_state contains the request state which was set in
 * state[REAL]
 *
 * Returns: True if locked. False otherwise
 */
static bool cons_try_acquire_spin(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state cur, new;
	bool ret = false;
	int timeout;

	/* Now wait for the other side to hand over */
	for (timeout = ctxt->spinwait_max_us; timeout >= 0; timeout--) {
		if (cons_check_panic())
			goto cleanup;

		cons_state_read(con, STATE_REAL, &cur);
		/*
		 * This might have raced with a new requester coming in
		 * after the lock was handed over. So the request pends now
		 * for the current context with higher priority.
		 */
		if (cons_state_bits_match(cur, ctxt->hov_state))
			goto success;

		/*
		 * When state changed since the request was made give up as
		 * it is not longer consistent. This must include
		 * state::req_prio.
		 */
		if (cur.bits != ctxt->req_state.bits)
			goto cleanup;

		/*
		 * Finally check whether the handover state is still
		 * the same.
		 */
		cons_state_read(con, STATE_HANDOVER, &cur);
		if (cur.atom != ctxt->hov_state.atom)
			goto cleanup;

		/* Account time */
		udelay(1);
	}

	/*
	 * Timeout. Cleanup the handover state and carefully try to undo
	 * req_prio in real state.
	 */
	cons_cleanup_handover(ctxt);

	cons_state_read(con, STATE_REAL, &cur);
	do {
		/*
		 * The timeout might have raced with the owner coming late
		 * and handing it over gracefully.
		 */
		if (cur.bits == ctxt->hov_state.bits)
			goto success;
		/*
		 * Validate that the state matches with the state at
		 * request time.
		 */
		if (cur.bits != ctxt->req_state.bits)
			return false;

		copy_full_state(new, cur);
		new.req_prio = 0;
	} while (!cons_state_try_cmpxchg(con, STATE_REAL, &cur, &new));
	/* Reset worked */
	return false;

success:
	/* Store the real state */
	copy_full_state(ctxt->state, cur);
	ctxt->hostile = false;
	ret = true;

cleanup:
	cons_cleanup_handover(ctxt);
	return ret;
}

/**
 * __cons_try_acquire - Try to acquire the console for printk output
 * @ctxt:	Pointer to an aquire context which contains
 *		all information about the acquire mode
 *
 * Returns: True if the acquire was successful. False on fail.
 *
 * In case of success @ctxt->state contains the acquisition
 * state.
 *
 * In case of fail @ctxt->old_state contains the state
 * which was read from @con->state for analysis by the caller.
 */
static bool __cons_try_acquire(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	unsigned int cpu = smp_processor_id();
	struct cons_state old, new;

	if (WARN_ON_ONCE(!(con->flags & CON_NO_BKL)))
		return false;

	cons_state_read(con, STATE_REAL, &old);

again:
	if (cons_check_panic())
		return false;

	/* Preserve it for the caller and for spinwait */
	copy_full_state(ctxt->old_state, old);

	if (!cons_state_ok(old))
		return false;

	/* Set up the new state for takeover */
	copy_full_state(new, old);
	new.locked = 1;
	new.thread = ctxt->thread;
	new.cur_prio = ctxt->prio;
	new.req_prio = CONS_PRIO_NONE;
	new.cpu = cpu;

	/* Attempt to acquire it directly if unlocked */
	if (!old.locked) {
		if (!cons_state_try_cmpxchg(con, STATE_REAL, &old, &new))
			goto again;

		ctxt->hostile = false;
		copy_full_state(ctxt->state, new);
		goto success;
	}

	/*
	 * Give up if the calling context is the printk thread. The
	 * atomic writer will wake the thread when it is done with
	 * the important output.
	 */
	if (ctxt->thread)
		return false;

	/*
	 * If the active context is on the same CPU then there is
	 * obviously no handshake possible.
	 */
	if (old.cpu == cpu)
		goto check_hostile;

	/*
	 * If the caller did not request spin-waiting or a request with the
	 * same or higher priority is pending then check whether a hostile
	 * takeover is due.
	 */
	if (!ctxt->spinwait || old.req_prio >= ctxt->prio)
		goto check_hostile;

	/* Proceed further with spin acquire */
	if (!cons_setup_handover(ctxt))
		return false;

	/*
	 * Setup the request in state[REAL]. Hand in the state, which was
	 * used to make the decision to spinwait above, for comparison.
	 */
	if (!cons_setup_request(ctxt, old))
		return false;

	/* Now spin on it */
	if (!cons_try_acquire_spin(ctxt))
		return false;
success:
	/* Common updates on success */
	return true;

check_hostile:
	if (!ctxt->hostile)
		return false;

	if (!cons_state_try_cmpxchg(con, STATE_REAL, &old, &new))
		goto again;

	ctxt->hostile = true;
	copy_full_state(ctxt->state, new);
	goto success;
}

/**
 * cons_try_acquire - Try to acquire the console for printk output
 * @ctxt:	Pointer to an aquire context which contains
 *		all information about the acquire mode
 *
 * Returns: True if the acquire was successful. False on fail.
 *
 * In case of success @ctxt->state contains the acquisition
 * state.
 *
 * In case of fail @ctxt->old_state contains the state
 * which was read from @con->state for analysis by the caller.
 */
static bool __maybe_unused cons_try_acquire(struct cons_context *ctxt)
{
	if (__cons_try_acquire(ctxt))
		return true;

	ctxt->state.atom = 0;
	return false;
}

/**
 * __cons_release - Release the console after output is done
 * @ctxt:	The acquire context which contains the state
 *		at cons_try_acquire()
 *
 * Returns:	True if the release was regular
 *
 *		False if the console is in unusable state or was handed over
 *		with handshake or taken	over hostile without handshake.
 *
 * The return value tells the caller whether it needs to evaluate further
 * printing.
 */
static bool __cons_release(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state old, new, hstate;

	if (WARN_ON_ONCE(!(con->flags & CON_NO_BKL)))
		return false;

	cons_state_read(con, STATE_REAL, &old);

again:
	if (!cons_state_full_match(old, ctxt->state))
		return false;

	/*
	 * Release it directly when:
	 * - the console has been disabled
	 * - no handover request is pending
	 */
	if (!cons_state_ok(old) || !old.req_prio)
		goto unlock;

	/* Read the handover target state */
	cons_state_read(con, STATE_HANDOVER, &hstate);

	/* If the waiter gave up hstate is 0 */
	if (!hstate.atom)
		goto unlock;

	/*
	 * If a higher priority waiter raced against a lower priority
	 * waiter then wait for it to update the real state.
	 */
	if (hstate.cur_prio != old.req_prio)
		goto again;

	/* Switch the state and preserve the sequence on 64bit */
	copy_bit_state(new, hstate);
	copy_seq_state64(new, old);
	if (!cons_state_try_cmpxchg(con, STATE_REAL, &old, &new))
		goto again;

	return true;

unlock:
	copy_full_state(new, old);
	new.locked = 0;
	new.thread = 0;
	new.cur_prio = CONS_PRIO_NONE;
	new.req_prio = CONS_PRIO_NONE;

	if (!cons_state_try_cmpxchg(con, STATE_REAL, &old, &new))
		goto again;

	return true;
}

/**
 * cons_release - Release the console after output is done
 * @ctxt:	The acquire context which contains the state
 *		at cons_try_acquire()
 *
 * Returns:	True if the release was regular
 *
 *		False if the console is in unusable state or was handed over
 *		with handshake or taken	over hostile without handshake.
 *
 * The return value tells the caller whether it needs to evaluate further
 * printing.
 */
static bool __maybe_unused cons_release(struct cons_context *ctxt)
{
	bool ret = __cons_release(ctxt);

	ctxt->state.atom = 0;
	return ret;
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
