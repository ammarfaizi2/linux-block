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

static bool cons_release(struct cons_context *ctxt);

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
 * cons_context_set_text_buf - Set the output text buffer for the current context
 * @ctxt:	Pointer to the aquire context
 *
 * Buffer selection:
 *   1) Early boot uses the console builtin buffer
 *   2) Threads use the console builtin buffer
 *   3) All other context use the per CPU buffers
 *
 * This guarantees that there is no concurrency on the output records
 * ever. Per CPU nesting is not a problem at all. The takeover logic
 * tells the interrupted context that the buffer has been overwritten.
 *
 * There are two critical regions which matter:
 *
 * 1) Context is filling the buffer with a record. After interruption
 *    it continues to sprintf() the record and before it goes to
 *    write it out, it checks the state, notices the takeover, discards
 *    the content and backs out.
 *
 * 2) Context is in a unsafe critical region in the driver. After
 *    interruption it might read overwritten data from the output
 *    buffer. When it leaves the critical region it notices and backs
 *    out. Hostile takeovers in driver critical regions are best effort
 *    and there is not much which can be done about that.
 */
static void cons_context_set_text_buf(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;

	/* Early boot or allocation fail? */
	if (!con->pcpu_data)
		ctxt->txtbuf = &con->ctxt_data.txtbuf;
	else
		ctxt->txtbuf = &(this_cpu_ptr(con->pcpu_data)->txtbuf);
}

/**
 * cons_forward_sequence - Helper function forward the sequence
 * @con:	Console to work on
 *
 * Forward @con->atomic_seq to the oldest available record. For init
 * only. Do not use for runtime updates.
 */
static void cons_forward_sequence(struct console *con)
{
	u32 seq = (u32)prb_first_valid_seq(prb);
#ifdef CONFIG_64BIT
	struct cons_state state;

	cons_state_read(con, STATE_REAL, &state);
	state.seq = seq;
	cons_state_set(con, STATE_REAL, &state);
#else
	atomic_set(&ACCESS_PRIVATE(con, atomic_seq), seq);
#endif
}

/**
 * cons_context_sequence_init - Retrieve the last printed sequence number
 * @ctxt:	Pointer to an aquire context which contains
 *		all information about the acquire mode
 *
 * On return the retrieved sequence number is stored in ctxt->oldseq.
 *
 * The sequence number is safe in forceful takeover situations.
 *
 * Either the writer succeded to update before it got interrupted
 * or it failed. In the latter case the takeover will print the
 * same line again.
 *
 * The sequence is only the lower 32bits of the ringbuffer sequence. The
 * ringbuffer must be 2^31 records ahead to get out of sync. This needs
 * some care when starting a console, i.e setting the sequence to 0 is
 * wrong. It has to be set to the oldest valid sequence in the ringbuffer
 * as that cannot be more than 2^31 records away
 *
 * On 64bit the 32bit sequence is part of console::state which is saved
 * in @ctxt->state. This prevents the 32bit update race.
 */
static void cons_context_sequence_init(struct cons_context *ctxt)
{
	u64 rbseq;

#ifdef CONFIG_64BIT
	ctxt->oldseq = ctxt->state.seq;
#else
	ctxt->oldseq = atomic_read(&ACCESS_PRIVATE(ctxt->console, atomic_seq));
#endif

	/*
	 * The sequence is only the lower 32bits of the ringbuffer
	 * sequence. So it needs to be expanded to 64bit. Get the next
	 * sequence number from the ringbuffer and fold it.
	 */
	rbseq = prb_next_seq(prb);
	ctxt->oldseq = rbseq - ((u32)rbseq - (u32)ctxt->oldseq);
	ctxt->newseq = ctxt->oldseq;
}

/**
 * cons_sequence_try_update - Try to update the sequence number
 * @ctxt:	Pointer to an aquire context which contains
 *		all information about the acquire mode
 *
 * Returns:	True on success
 *		False on fail.
 *
 * Internal helper as the logic is different on 32bit and 64bit.
 *
 * On 32 bit the sequence is seperate from state and therefore
 * subject to a subtle race in the case of hostile takeovers.
 *
 * On 64 bit the sequence is part of the state and therefore safe
 * vs. hostile takeovers.
 *
 * In case of fail the console has been taken over and @ctxt is
 * invalid. Caller has to reacquire the console.
 */
#ifdef CONFIG_64BIT
static bool cons_sequence_try_update(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	struct cons_state old, new;

	cons_state_read(con, STATE_REAL, &old);
	do {
		/* Full state compare including sequence */
		if (!cons_state_full_match(old, ctxt->state))
			return false;

		/* Preserve bit state */
		copy_bit_state(new, old);
		new.seq = ctxt->newseq;

		/*
		 * Can race with hostile takeover or with a handover
		 * request.
		 */
	} while (!cons_state_try_cmpxchg(con, STATE_REAL, &old, &new));

	copy_full_state(ctxt->state, new);
	ctxt->oldseq = ctxt->newseq;

	return true;
}
#else
static bool cons_sequence_try_update(struct cons_context *ctxt)
{
	struct console *con = ctxt->console;
	unsigned long old, new, cur;
	struct cons_state state;
	int pcpu;

	/*
	 * There is a corner case which needs to be considered here:
	 *
	 * CPU0			CPU1
	 * printk()
	 *  acquire()		-> emergency
	 *  write()		   acquire()
	 *  update_seq()
	 *    state == OK
	 * --> NMI
	 *			   takeover()
	 * <---			     write()
	 *  cmpxchg() succeeds	     update_seq()
	 *			     cmpxchg() fails
	 *
	 * There is nothing which can be done about this other than having
	 * yet another state bit which needs to be tracked and analyzed,
	 * but fails to cover the problem completely.
	 *
	 * No other scenarios expose such a problem. On same CPU takeovers
	 * the cmpxchg() always fails on the interrupted context after the
	 * interrupting context finished printing, but that's fine as it
	 * does not own the console anymore. The state check after the
	 * failed cmpxchg prevents that.
	 */
	cons_state_read(con, STATE_REAL, &state);
	/* Sequence is not part of cons_state on 32bit */
	if (!cons_state_bits_match(state, ctxt->state))
		return false;

	/*
	 * Get the original sequence number which was retrieved
	 * from @con->atomic_seq. @con->atomic_seq should be still
	 * the same. 32bit truncates. See cons_context_set_sequence().
	 */
	old = (unsigned long)ctxt->oldseq;
	new = (unsigned long)ctxt->newseq;
	cur = atomic_cmpxchg(&ACCESS_PRIVATE(con, atomic_seq), old, new);
	if (cur == old) {
		ctxt->oldseq = ctxt->newseq;
		return true;
	}

	/*
	 * Reread the state. If the state does not own the console anymore
	 * then it cannot touch the sequence again.
	 */
	cons_state_read(con, STATE_REAL, &state);
	/* Sequence is not part of cons_state on 32bit */
	if (!cons_state_bits_match(state, ctxt->state))
		return false;

	/* If panic and not on the panic CPU, drop the lock */
	pcpu = atomic_read(&panic_cpu);
	if (pcpu != PANIC_CPU_INVALID && pcpu != smp_processor_id())
		goto unlock;

	if (pcpu == smp_processor_id()) {
		/*
		 * This is the panic CPU. Emitting a warning here does not
		 * help at all. The callchain is clear and the priority is
		 * to get the messages out. In the worst case duplicated
		 * ones. That's a job for postprocessing.
		 */
		atomic_set(&ACCESS_PRIVATE(con, atomic_seq), new);
		ctxt->oldseq = ctxt->newseq;
		return true;
	}

	/*
	 * Only emit a warning when this happens outside of a panic
	 * situation as on panic it's neither useful nor helping to let the
	 * panic CPU get the important stuff out.
	 */
	WARN_ON_ONCE(pcpu == PANIC_CPU_INVALID);

unlock:
	cons_release(ctxt);
	return false;
}
#endif

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
	cons_context_sequence_init(ctxt);
	cons_context_set_text_buf(ctxt);
	return true;

check_hostile:
	if (!ctxt->hostile)
		return false;

	if (!cons_state_try_cmpxchg(con, STATE_REAL, &old, &new))
		goto again;

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
 * cons_alloc_percpu_data - Allocate percpu data for a console
 * @con:	Console to allocate for
 */
static void cons_alloc_percpu_data(struct console *con)
{
	if (!printk_percpu_data_ready())
		return;

	con->pcpu_data = alloc_percpu(typeof(*con->pcpu_data));
	if (con->pcpu_data)
		return;

	con_printk(KERN_WARNING, con, "Failed to allocate percpu buffers\n");
}

/**
 * cons_free_percpu_data - Free percpu data of a console on unregister
 * @con:	Console to clean up
 */
static void cons_free_percpu_data(struct console *con)
{
	if (!con->pcpu_data)
		return;

	free_percpu(con->pcpu_data);
	con->pcpu_data = NULL;
}

/**
 * console_can_proceed - Check whether printing can proceed
 * @wctxt:	The write context which was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked after the record was dumped into the assigned record
 * buffer and at appropriate safe places in the driver.  For unsafe driver
 * sections see console_enter_unsafe().
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully.  The buffer
 * content is not longer trusted either and the console lock is not longer
 * held.
 */
bool console_can_proceed(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	struct cons_state state;

	cons_state_read(con, STATE_REAL, &state);
	/* Store it for analyis or reuse */
	copy_full_state(ctxt->old_state, state);

	/*
	 * If the state aside of req_prio is not longer matching, console
	 * was taken over.
	 */
	if (!cons_state_full_match(state, ctxt->state))
		return false;

	/*
	 * Having a safe point for take over and eventually a few
	 * duplicated characters or a full line is way better than a
	 * hostile takeover. Post processing can take care of the garbage.
	 * Continue if the requested priority is not sufficient.
	 */
	if (state.req_prio <= state.cur_prio)
		return true;

	/* Release and hand over */
	cons_release(ctxt);
	/*
	 * This does not check whether the handover succeeded. The
	 * outermost callsite has to do the final check whether printing
	 * should continue or not. The console is unlocked already so go
	 * back all the way instead of trying to implement heuristics in
	 * tons of places.
	 */
	return false;
}

/**
 * __console_update_unsafe - Update the unsafe bit in @con->atomic_state
 * @wctxt:	The write context which was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked before a unsafe driver section is entered.
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully.  The buffer
 * content is not longer trusted either and the console lock is not longer
 * held.
 *
 * Internal helper to avoid duplicated code
 */
static bool __console_update_unsafe(struct cons_write_context *wctxt, bool unsafe)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	struct cons_state new;

	do  {
		if (!console_can_proceed(wctxt))
			return false;
		/*
		 * console_can_proceed() saved the real state in
		 * ctxt->old_state
		 */
		copy_full_state(new, ctxt->old_state);
		new.unsafe = unsafe;

	} while (!cons_state_try_cmpxchg(con, STATE_REAL, &ctxt->old_state, &new));

	copy_full_state(ctxt->state, new);
	return true;
}

/**
 * console_enter_unsafe - Enter an unsafe region in the driver
 * @wctxt:	The write context which was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked before a unsafe driver section is entered.
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully.  The buffer
 * content is not longer trusted either and the console lock is not longer
 * held.
 */
bool console_enter_unsafe(struct cons_write_context *wctxt)
{
	return __console_update_unsafe(wctxt, true);
}

/**
 * console_exit_unsafe - Exit an unsafe region in the driver
 * @wctxt:	The write context which was handed to the write function
 *
 * Returns:	True if the state is correct. False if a handover
 *		has been requested or if the console was taken
 *		over.
 *
 * Must be invoked before a unsafe driver section is exited.
 *
 * When this function returns false then the calling context is not allowed
 * to go forward and has to back out immediately and carefully.  The buffer
 * content is not longer trusted either and the console lock is not longer
 * held.
 */
bool console_exit_unsafe(struct cons_write_context *wctxt)
{
	return __console_update_unsafe(wctxt, false);
}

static bool cons_fill_outbuf(struct cons_outbuf_desc *desc);

/**
 * cons_get_record - Fill the buffer with the next pending ringbuffer record
 * @wctxt:	The write context which will be handed to the write function
 *
 * Returns:	True if there are records to print. If the output buffer is
 *		filled @wctxt->outbuf points to the text, otherwise it is NULL.
 *
 *		False signals that there are no pending records anymore and
 *		the printing can stop.
 */
static bool cons_get_record(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	struct cons_outbuf_desc desc = {
		.txtbuf		= ctxt->txtbuf,
		.extmsg		= con->flags & CON_EXTENDED,
		.seq		= ctxt->newseq,
		.dropped	= ctxt->dropped,
	};
	bool progress = cons_fill_outbuf(&desc);

	ctxt->newseq = desc.seq;
	ctxt->dropped = desc.dropped;

	wctxt->pos = 0;
	wctxt->len = desc.len;
	wctxt->outbuf = desc.outbuf;
	return progress;
}

/**
 * cons_emit_record - Emit record in the acquired context
 * @wctxt:	The write context which will be handed to the write function
 *
 * Returns:	False if the operation was aborted (takeover)
 *		True otherwise
 *
 * In case of takeover the caller is not allowed to touch console state.
 * The console is owned by someone else. If the caller wants to print
 * more it has to reacquire the console first.
 *
 * If it returns true @wctxt->ctxt.backlog indicates whether there are
 * still records pending in the ringbuffer,
 */
static int __maybe_unused cons_emit_record(struct cons_write_context *wctxt)
{
	struct cons_context *ctxt = &ACCESS_PRIVATE(wctxt, ctxt);
	struct console *con = ctxt->console;
	bool done = false;

	/*
	 * @con->dropped is not protected in case of hostile takeovers so
	 * the update below is racy. Annotate it accordingly.
	 */
	ctxt->dropped = data_race(READ_ONCE(con->dropped));

	/* Fill the output buffer with the next record */
	ctxt->backlog = cons_get_record(wctxt);
	if (!ctxt->backlog)
		return true;

	/* Safety point. Don't touch state in case of takeover */
	if (!console_can_proceed(wctxt))
		return false;

	/* Counterpart to the read above */
	WRITE_ONCE(con->dropped, ctxt->dropped);

	/*
	 * In case of skipped records, Update sequence state in @con.
	 */
	if (!wctxt->outbuf)
		goto update;

	/* Tell the driver about potential unsafe state */
	wctxt->unsafe = ctxt->state.unsafe;

	if (!ctxt->thread && con->write_atomic) {
		done = con->write_atomic(con, wctxt);
	} else {
		cons_release(ctxt);
		WARN_ON_ONCE(1);
		return false;
	}

	/* If not done, the write was aborted due to takeover */
	if (!done)
		return false;

	ctxt->newseq++;
update:
	/*
	 * The sequence update attempt is not part of console_release()
	 * because in panic situations the console is not released by
	 * the panic CPU until all records are written. On 32bit the
	 * sequence is seperate from state anyway.
	 */
	return cons_sequence_try_update(ctxt);
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

	cons_alloc_percpu_data(con);
	cons_forward_sequence(con);
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
	cons_free_percpu_data(con);
}

#else /* CONFIG_PRINTK */
static inline void cons_nobkl_init(struct console *con) { }
static inline void cons_nobkl_cleanup(struct console *con) { }
static inline void cons_state_disable(struct console *con) { }
static inline void cons_state_enable(struct console *con) { }
#endif /* !CONFIG_PRINTK */
