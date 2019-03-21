// SPDX-License-Identifier: GPL-2.0
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/kasan-checks.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/errno.h>

#include <asm/byteorder.h>
#include <asm/word-at-a-time.h>

#define IS_UNALIGNED(addr) (((long __force)(addr)) & (sizeof(long) - 1))

/*
 * Do a strncpy, return length of string without final '\0'.
 * 'count' is the user-supplied count (return 'count' if we
 * hit it), 'max' is the address space maximum (and we return
 * -EFAULT if we hit it).
 */
static inline long do_strncpy_from_user(char *dst, const char __user *src, long count, unsigned long max)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	long res = 0;

	/*
	 * Truncate 'max' to the user-specified limit, so that
	 * we only have one limit we need to check in the loop
	 */
	if (likely(max > count))
		max = count;

	/*
	 * First handle any unaligned prefix of src.
	 */
	while (IS_UNALIGNED(src+res) && max) {
		char c;

		unsafe_get_user(c, src+res, efault);
		dst[res] = c;
		if (!c)
			return res;
		res++;
		max--;
	}

	/*
	 * Now we know that src + res is aligned.  If dst is unaligned and
	 * we don't have efficient unaligned access, then keep going one
	 * byte at a time.  (This could be optimized, but it would make
	 * the code more complicated.
	 */
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (IS_UNALIGNED(dst + res))
		goto byte_at_a_time;
#endif

	while (max >= sizeof(unsigned long)) {
		/*
		 * src + res is aligned, so the reads in this loop will
		 * not cross a page boundary.
		 */
		unsigned long c, data;

		unsafe_get_user(c, (unsigned long __user *)(src+res), efault);

		if (has_zero(c, &data, &constants)) {
			long zero_pos;

			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			zero_pos = find_zero(data);

			/*
			 * Zero any bytes that we read past the end of the
			 * input so they don't end up in kernel memory.  This
			 * is for hardening -- omitting it is not a bug.
			 */
#ifdef __LITTLE_ENDIAN
			c &= (~0UL) >> (8 * (sizeof(long) - zero_pos));
#else
			c &= (~0UL) << (8 * (sizeof(long) - zero_pos));
#endif
			*(unsigned long *)(dst+res) = c;

			return res + zero_pos;
		}

		*(unsigned long *)(dst+res) = c;
		res += sizeof(unsigned long);
		max -= sizeof(unsigned long);
	}

byte_at_a_time: __maybe_unused;
	/*
	 * Finish the job one byte at a time.
	 */
	while (max) {
		char c;

		unsafe_get_user(c,src+res, efault);
		dst[res] = c;
		if (!c)
			return res;
		res++;
		max--;
	}

	/*
	 * Uhhuh. We hit 'max'. But was that the user-specified maximum
	 * too? If so, that's ok - we got as much as the user asked for.
	 */
	if (res >= count)
		return res;

	/*
	 * Nope: we hit the address space limit, and we still had more
	 * characters the caller would have wanted. That's an EFAULT.
	 */
efault:
	return -EFAULT;
}

/**
 * strncpy_from_user: - Copy a NUL terminated string from userspace.
 * @dst:   Destination address, in kernel space.  This buffer must be at
 *         least @count bytes long.
 * @src:   Source address, in user space.
 * @count: Maximum number of bytes to copy, including the trailing NUL.
 *
 * Copies a NUL-terminated string from userspace to kernel space.
 *
 * On success, returns the length of the string (not including the trailing
 * NUL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 *
 * If @count is smaller than the length of the string, copies @count bytes
 * and returns @count.
 */
long strncpy_from_user(char *dst, const char __user *src, long count)
{
	unsigned long max_addr, src_addr;

	if (unlikely(count <= 0))
		return 0;

	max_addr = user_addr_max();
	src_addr = (unsigned long)src;
	if (likely(src_addr < max_addr)) {
		unsigned long max = max_addr - src_addr;
		long retval;

		kasan_check_write(dst, count);
		check_object_size(dst, count, false);
		if (user_access_begin(src, max)) {
			retval = do_strncpy_from_user(dst, src, count, max);
			user_access_end();
			return retval;
		}
	}
	return -EFAULT;
}
EXPORT_SYMBOL(strncpy_from_user);

#ifdef CONFIG_UACCESS_SELFTEST

#include <linux/vmalloc.h>

/*
 * The intent of this selftest is to verify some properties of
 * strncpy_from_user():
 *
 *  - It returns the right value and copies the string faithfully.  This is
 *    verified in the cases where the whole string including NULL-terminator
 *    fits and where it doesn't.
 *
 * - It does not overrun the input buffer into the subsequent page.  Verified
 *   by running the tests using a vmalloced page (which comes with a guard
 *   page) and putting the buffers near the end.
 *
 * - It does not overrun the output buffer at all.  Verified by writing
 *   a canary at the end and verifying that the canary isn't changed.
 *
 * These tests are run with various mis-alignments of the input and output
 * buffers.
 */
static bool do_selftest(char *source_page, char *target_page,
			size_t len, size_t count,
			size_t source_offset, size_t target_offset)
{
	size_t i;
	size_t ret, expected_ret = min(count, len);
	char *source = source_page + source_offset;
	char *target = target_page + target_offset;

	if (WARN_ON(source_offset + len > PAGE_SIZE))
		return false;
	if (WARN_ON(target_offset + count > PAGE_SIZE))
		return false;

	memset(source_page, 0, PAGE_SIZE);
	for (i = 0; i < len; i++)
		source[i] = 'A' + i;

	memset(target_page, 0xff, PAGE_SIZE);
	ret = strncpy_from_user(target, (char __user __force *)source, count);
	if (WARN_ON(ret != expected_ret)) {
		pr_err("Tried to copy %lu bytes; got %lu; len was %lu\n",
		       (unsigned long)count, (unsigned long)ret,
		       (unsigned long)len);
		return false;
	}

	/* Check that the string was copied correctly. */
	if (WARN_ON(memcmp(source, target, expected_ret)))
		return false;

	/* Check that the NULL got copied if it fit. */
	if (count > len && WARN_ON(target[len] != 0))
		return false;

	/* Check that the target buffer was not overrun. */
	if (target_offset + count < PAGE_SIZE && WARN_ON(target[count] != (char)0xff))
		return false;

	return true;
}

static void strncpy_from_user_selftest(void)
{
	mm_segment_t old_fs = get_fs();
	char *source_page = vmalloc(PAGE_SIZE);
	char *target_page = vmalloc(PAGE_SIZE);

	size_t len;

	pr_info("selftest: testing strncpy_from_user\n");

	if (!source_page || !target_page)
		goto done;

	set_fs(KERNEL_DS);

	/* Check all lengths up to 31 bytes. */
	for (len = 0; len <= 31; len++) {
		/*
		 * Check all offsets between 0 and 7 bytes from last non-null
		 * source byte to end of page.
		 */
		size_t source_offset;

		for (source_offset = PAGE_SIZE - len - 7;
		     source_offset < PAGE_SIZE - len; source_offset++) {
			/* Check all counts from len-7 to len+7. */
			size_t count;

			for (count = max_t(long, 0, (long)len - 7);
				     count < len + 7; count++) {
				size_t target_offset;

				for (target_offset = PAGE_SIZE - count - 7;
				     target_offset < PAGE_SIZE - count; target_offset++) {
					if (!do_selftest(source_page, target_page,
							 len, count, source_offset,
							 target_offset))
						goto done;
				}
			}
		}
	}

	pr_info("selftest: strncpy_from_user test passed\n");

done:
	vfree(target_page);
	vfree(source_page);
	set_fs(old_fs);
}
late_initcall(strncpy_from_user_selftest);
#endif
