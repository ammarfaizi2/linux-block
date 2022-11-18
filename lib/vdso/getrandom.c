// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/time64.h>
#include <vdso/datapage.h>
#include <vdso/getrandom.h>
#include <asm/vdso/getrandom.h>
#include <asm/vdso/vsyscall.h>

#define MEMCPY_AND_ZERO_SRC(type, dst, src, len) do {				\
	while (len >= sizeof(type)) {						\
		__put_unaligned_t(type, __get_unaligned_t(type, src), dst);	\
		__put_unaligned_t(type, 0, src);				\
		dst += sizeof(type);						\
		src += sizeof(type);						\
		len -= sizeof(type);						\
	}									\
} while (0)

static void memcpy_and_zero_src(void *dst, void *src, size_t len)
{
	if (IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)) {
		if (IS_ENABLED(CONFIG_64BIT))
			MEMCPY_AND_ZERO_SRC(u64, dst, src, len);
		MEMCPY_AND_ZERO_SRC(u32, dst, src, len);
		MEMCPY_AND_ZERO_SRC(u16, dst, src, len);
	}
	MEMCPY_AND_ZERO_SRC(u8, dst, src, len);
}

/**
 * __cvdso_getrandom_data - Generic vDSO implementation of getrandom() syscall.
 * @rng_info:		Describes state of kernel RNG, memory shared with kernel.
 * @buffer:		Destination buffer to fill with random bytes.
 * @len:		Size of @buffer in bytes.
 * @flags:		Zero or more GRND_* flags.
 * @opaque_state:	Pointer to an opaque state area.
 *
 * This implements a "fast key erasure" RNG using ChaCha20, in the same way that the kernel's
 * getrandom() syscall does. It periodically reseeds its key from the kernel's RNG, at the same
 * schedule that the kernel's RNG is reseeded. If the kernel's RNG is not ready, then this always
 * calls into the syscall.
 *
 * @opaque_state *must* be allocated using the vgetrandom_alloc() syscall.  Unless external locking
 * is used, one state must be allocated per thread, as it is not safe to call this function
 * concurrently with the same @opaque_state. However, it is safe to call this using the same
 * @opaque_state that is shared between main code and signal handling code, within the same thread.
 *
 * Returns the number of random bytes written to @buffer, or a negative value indicating an error.
 */
static __always_inline ssize_t
__cvdso_getrandom_data(const struct vdso_rng_data *rng_info, void *buffer, size_t len,
		       unsigned int flags, void *opaque_state)
{
	ssize_t ret = min_t(size_t, INT_MAX & PAGE_MASK /* = MAX_RW_COUNT */, len);
	struct vgetrandom_state *state = opaque_state;
	size_t batch_len, nblocks, orig_len = len;
	unsigned long current_generation;
	void *orig_buffer = buffer;
	u32 counter[2] = { 0 };
	bool in_use, have_retried = false;

	/* The state must not straddle a page, since pages can be zeroed at any time. */
	if (unlikely(((unsigned long)opaque_state & ~PAGE_MASK) + sizeof(*state) > PAGE_SIZE))
		goto fallback_syscall;

	/*
	 * If the kernel's RNG is not yet ready, then it's not possible to provide random bytes from
	 * userspace, because A) the various @flags require this to block, or not, depending on
	 * various factors unavailable to userspace, and B) the kernel's behavior before the RNG is
	 * ready is to reseed from the entropy pool at every invocation.
	 */
	if (unlikely(!READ_ONCE(rng_info->is_ready)))
		goto fallback_syscall;

	/*
	 * This condition is checked after @rng_info->is_ready, because before the kernel's RNG is
	 * initialized, the @flags parameter may require this to block or return an error, even when
	 * len is zero.
	 */
	if (unlikely(!len))
		return 0;

	/*
	 * @state->in_use is basic reentrancy protection against this running in a signal handler
	 * with the same @opaque_state, but obviously not atomic wrt multiple CPUs or more than one
	 * level of reentrancy. If a signal interrupts this after reading @state->in_use, but before
	 * writing @state->in_use, there is still no race, because the signal handler will run to
	 * its completion before returning execution.
	 */
	in_use = READ_ONCE(state->in_use);
	if (unlikely(in_use))
		goto fallback_syscall;
	WRITE_ONCE(state->in_use, true);

retry_generation:
	/*
	 * @rng_info->generation must always be read here, as it serializes @state->key with the
	 * kernel's RNG reseeding schedule.
	 */
	current_generation = READ_ONCE(rng_info->generation);

	/*
	 * If @state->generation doesn't match the kernel RNG's generation, then it means the
	 * kernel's RNG has reseeded, and so @state->key is reseeded as well.
	 */
	if (unlikely(state->generation != current_generation)) {
		/*
		 * Write the generation before filling the key, in case of fork. If there is a fork
		 * just after this line, the two forks will get different random bytes from the
		 * syscall, which is good. However, were this line to occur after the getrandom
		 * syscall, then both child and parent could have the same bytes and the same
		 * generation counter, so the fork would not be detected. Therefore, write
		 * @state->generation before the call to the getrandom syscall.
		 */
		WRITE_ONCE(state->generation, current_generation);

		/* Prevent the syscall from being reordered wrt current_generation. */
		barrier();

		/* Reseed @state->key using fresh bytes from the kernel. */
		if (getrandom_syscall(state->key, sizeof(state->key), 0) != sizeof(state->key)) {
			/*
			 * If the syscall failed to refresh the key, then @state->key is now
			 * invalid, so invalidate the generation so that it is not used again, and
			 * fallback to using the syscall entirely.
			 */
			WRITE_ONCE(state->generation, 0);

			/*
			 * Set @state->in_use to false only after the last write to @state in the
			 * line above.
			 */
			WRITE_ONCE(state->in_use, false);

			goto fallback_syscall;
		}

		/*
		 * Set @state->pos to beyond the end of the batch, so that the batch is refilled
		 * using the new key.
		 */
		state->pos = sizeof(state->batch);
	}

	/* Set len to the total amount of bytes that this function is allowed to read, ret. */
	len = ret;
more_batch:
	/*
	 * First use bytes out of @state->batch, which may have been filled by the last call to this
	 * function.
	 */
	batch_len = min_t(size_t, sizeof(state->batch) - state->pos, len);
	if (batch_len) {
		/* Zeroing at the same time as memcpying helps preserve forward secrecy. */
		memcpy_and_zero_src(buffer, state->batch + state->pos, batch_len);
		state->pos += batch_len;
		buffer += batch_len;
		len -= batch_len;
	}

	if (!len) {
		/* Prevent the loop from being reordered wrt ->generation. */
		barrier();

		/*
		 * Since @rng_info->generation will never be 0, re-read @state->generation, rather
		 * than using the local current_generation variable, to learn whether a fork
		 * occurred or if @state was zeroed due to memory pressure. Primarily, though, this
		 * indicates whether the kernel's RNG has reseeded, in which case generate a new key
		 * and start over.
		 */
		if (unlikely(READ_ONCE(state->generation) != READ_ONCE(rng_info->generation))) {
			/*
			 * Prevent this from looping forever in case of low memory or racing with a
			 * user force-reseeding the kernel's RNG using the ioctl.
			 */
			if (have_retried) {
				WRITE_ONCE(state->in_use, false);
				goto fallback_syscall;
			}

			have_retried = true;
			buffer = orig_buffer;
			goto retry_generation;
		}

		/*
		 * Set @state->in_use to false only when there will be no more reads or writes of
		 * @state.
		 */
		WRITE_ONCE(state->in_use, false);
		return ret;
	}

	/* Generate blocks of RNG output directly into @buffer while there's enough room left. */
	nblocks = len / CHACHA_BLOCK_SIZE;
	if (nblocks) {
		__arch_chacha20_blocks_nostack(buffer, state->key, counter, nblocks);
		buffer += nblocks * CHACHA_BLOCK_SIZE;
		len -= nblocks * CHACHA_BLOCK_SIZE;
	}

	BUILD_BUG_ON(sizeof(state->batch_key) % CHACHA_BLOCK_SIZE != 0);

	/* Refill the batch and then overwrite the key, in order to preserve forward secrecy. */
	__arch_chacha20_blocks_nostack(state->batch_key, state->key, counter,
				       sizeof(state->batch_key) / CHACHA_BLOCK_SIZE);

	/* Since the batch was just refilled, set the position back to 0 to indicate a full batch. */
	state->pos = 0;
	goto more_batch;

fallback_syscall:
	return getrandom_syscall(orig_buffer, orig_len, flags);
}

static __always_inline ssize_t
__cvdso_getrandom(void *buffer, size_t len, unsigned int flags, void *opaque_state)
{
	return __cvdso_getrandom_data(__arch_get_vdso_rng_data(), buffer, len, flags, opaque_state);
}
