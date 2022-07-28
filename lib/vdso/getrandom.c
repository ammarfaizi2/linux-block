// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <vdso/datapage.h>
#include <asm/vdso/getrandom.h>
#include <asm/vdso/vsyscall.h>
#include <asm/page.h>
#include <uapi/linux/mman.h>
#include "../crypto/chacha.c"

struct getrandom_state {
	u64 last_reseed;
	unsigned long generation;
	union {
		struct {
			u8 key[CHACHA_KEY_SIZE];
			u8 batch[CHACHA_BLOCK_SIZE * 3 / 2];
		};
		u8 key_batch[CHACHA_BLOCK_SIZE * 2];
	};
	u8 pos;
	bool not_forked;
};

static void memcpy_and_zero(void *dst, void *src, size_t len)
{
#define CASCADE(type) \
	while (len >= sizeof(type)) { \
		*(type *)dst = *(type *)src; \
		*(type *)src = 0; \
		dst += sizeof(type); \
		src += sizeof(type); \
		len -= sizeof(type); \
	}
#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#if BITS_PER_LONG == 64
	CASCADE(u64);
#endif
	CASCADE(u32);
	CASCADE(u16);
#endif
	CASCADE(u8);
#undef CASCADE
}

static __always_inline ssize_t
__cvdso_getrandom(void *opaque_state, void *buffer, size_t len, unsigned int flags)
{
	struct getrandom_state *state = opaque_state;
	const struct vdso_rng_data *rng_info = __arch_get_vdso_rng_data();
	const struct vdso_data *timebase = &__arch_get_vdso_data()[CS_HRES_COARSE];
	const struct vdso_timestamp *course_mono = &timebase->basetime[CLOCK_MONOTONIC_COARSE];
	u32 chacha_state[CHACHA_STATE_WORDS];
	ssize_t ret = min_t(size_t, MAX_RW_COUNT, len);
	size_t batch_len;

	if (unlikely(!rng_info->is_ready))
		return getrandom_syscall(buffer, len, flags);

	if (unlikely(!len))
		return 0;

	if (unlikely(!READ_ONCE(state->not_forked)))
		state->not_forked = true;

retry_generation:
	if (unlikely(state->generation != READ_ONCE(rng_info->generation) ||
		     /* 15 sec is crude approximation of crng_has_old_seed(). In the future,
		      * export this in rng_info->expiration, or similar. Needs improvement. */
		     READ_ONCE(course_mono->sec) - state->last_reseed > 15)) {
		if (getrandom_syscall(state->key, sizeof(state->key), 0) != sizeof(state->key))
			return getrandom_syscall(buffer, len, flags);
		/* We shouldn't be reading rng_info->generation afterwards, as technically it could
		 * be bumped in between these two lines. Instead this should be set to the value
		 * read in the `if ()` above. But in fact, the lazy semantics of generation bumping
		 * always make this happen. So live with this for now. Needs improvement. */
		state->generation = READ_ONCE(rng_info->generation);
		state->last_reseed = READ_ONCE(course_mono->sec);
		state->pos = sizeof(state->batch);
	}

	len = ret;
more_batch:
	batch_len = min_t(size_t, sizeof(state->batch) - state->pos, len);
	if (batch_len) {
		memcpy_and_zero(buffer, state->batch, batch_len);
		state->pos += batch_len;
		buffer += batch_len;
		len -= batch_len;
	}
	if (!len) {
		if (unlikely(state->generation != READ_ONCE(rng_info->generation)))
			goto retry_generation;
		if (unlikely(!READ_ONCE(state->not_forked))) {
			state->not_forked = true;
			goto retry_generation;
		}
		return ret;
	}

	chacha_init_consts(chacha_state);
	memcpy(&chacha_state[4], state->key, CHACHA_KEY_SIZE);
	memset(&chacha_state[12], 0, sizeof(u32) * 4);

	while (len >= CHACHA_BLOCK_SIZE) {
		chacha20_block(chacha_state, buffer);
		if (unlikely(chacha_state[12] == 0))
			++chacha_state[13];
		buffer += CHACHA_BLOCK_SIZE;
		len -= CHACHA_BLOCK_SIZE;
	}

	chacha20_block(chacha_state, state->key_batch);
	if (unlikely(chacha_state[12] == 0))
		++chacha_state[13];
	chacha20_block(chacha_state, state->key_batch + CHACHA_BLOCK_SIZE);
	state->pos = 0;
	memzero_explicit(chacha_state, sizeof(chacha_state));
	goto more_batch;
}

static __always_inline void *
__cvdso_getrandom_alloc(size_t *num, size_t *size_per_each)
{
	void *state;
	size_t alloc_size;

	alloc_size = size_mul(*num, sizeof(struct getrandom_state));
	if (alloc_size == SIZE_MAX)
		return NULL;
	alloc_size = roundup(alloc_size, PAGE_SIZE);

	state = mmap_syscall(NULL, alloc_size, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	if (state == (void *)~0UL)
		return NULL;

	if (madvise_syscall(state, alloc_size, MADV_WIPEONFORK)) {
		munmap_syscall(state, alloc_size);
		return NULL;
	}

	*num = alloc_size / sizeof(struct getrandom_state);
	*size_per_each = sizeof(struct getrandom_state);
	return state;
}
