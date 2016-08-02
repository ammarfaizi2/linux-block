/* Deterministically hash kernel modules for later verification
 *
 * Copyright (c) 2016 Andrew Lutomirski
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * You may, at your option, use, redistribute, or modify this software
 * under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * Q: Why is this written in C?
 * A: Because the kernel doesn't depend on Perl or Python and using
 *    coreutils and sh to do this is miserable.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/sha.h>

struct sha256hash {
	unsigned char val[32];
};

struct hash_state {
	size_t size, capacity;
	struct sha256hash *hashes;
};

static int cmp_hash(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct sha256hash));
}

static void do_one_module(struct hash_state *state, const char *modname)
{
	int fd;
	char buf[16384];
	SHA256_CTX ctx;

	if (state->size >= state->capacity) {
		size_t newcap = state->capacity * 2;
		if (newcap < 128)
			newcap = 128;
		state->hashes = realloc(state->hashes,
					newcap * sizeof(struct sha256hash));
		state->capacity = newcap;
	}

	SHA256_Init(&ctx);

	fd = open(modname, O_RDONLY);
	if (fd == -1)
		err(1, modname);
	while (1) {
		ssize_t ret = read(fd, buf, sizeof(buf));
		if (ret == 0)
			break;
		if (ret < 0)
			err(1, "read");
		SHA256_Update(&ctx, buf, ret);
	}
	close(fd);

	SHA256_Final(state->hashes[state->size].val, &ctx);
	state->size++;
}

static void writeall(const void *buf, size_t len)
{
	while (len) {
		size_t ret = fwrite(buf, 1, len, stdout);
		if (ret == 0)
			err(1, "fwrite");
		len -= ret;
		buf = (const void *)((const char *)buf + ret);
	}
}

int main(int argc, char **argv)
{
	struct hash_state state = {};

	while (1) {
		char modname[PATH_MAX + 2];
		size_t len;
		if (!fgets(modname, sizeof(modname), stdin))
			break;

		len = strlen(modname);
		if (len > PATH_MAX)
			errx(1, "filename is too long");
		if (!len)
			continue;
		modname[len - 1] = '\0';

		do_one_module(&state, modname);
	}

	if (ferror(stdin) || !feof(stdin))
		err(1, "failed to read from stdin");

	qsort(state.hashes, state.size, sizeof(state.hashes[0]), cmp_hash);

	writeall(state.hashes, state.size * sizeof(state.hashes[0]));

	return 0;
}
