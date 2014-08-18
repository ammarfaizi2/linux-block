/*
 * Copyright (C) 2014, Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
 *
 * Released under the GPL v2. (and only v2, not any later version)
 */
#include "poll.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

void fdarray__init(struct fdarray *fda)
{
	fda->entries = NULL;
	fda->nr = fda->nr_alloc = 0;
}

int fdarray__grow(struct fdarray *fda, int hint)
{
	int nr_alloc = fda->nr_alloc + hint;
	size_t size = sizeof(struct pollfd) * nr_alloc;
	struct pollfd *entries = realloc(fda->entries, size);

	if (entries == NULL)
		return -ENOMEM;

	fda->nr_alloc = nr_alloc;
	fda->entries  = entries;
	return 0;
}

struct fdarray *fdarray__new(int nr_alloc)
{
	struct fdarray *fda = calloc(1, sizeof(*fda));

	if (fda != NULL) {
		if (fdarray__grow(fda, nr_alloc)) {
			free(fda);
			fda = NULL;
		}
	}

	return fda;
}

void fdarray__exit(struct fdarray *fda)
{
	free(fda->entries);
	fdarray__init(fda);
}

void fdarray__delete(struct fdarray *fda)
{
	fdarray__exit(fda);
	free(fda);
}

int fdarray__add(struct fdarray *fda, int fd)
{
	/*
	 * XXX: 64 is arbitrary, just not to call realloc at each fd.
	 *	Find a better autogrowing heuristic
	 */
	if (fda->nr == fda->nr_alloc &&
	    fdarray__grow(fda, 64) < 0)
		return -ENOMEM;

	fcntl(fd, F_SETFL, O_NONBLOCK);
	fda->entries[fda->nr].fd = fd;
	fda->entries[fda->nr].events = POLLIN | POLLERR | POLLHUP;
	fda->nr++;
	return 0;
}

int fdarray__filter(struct fdarray *fda, short revents_and_mask)
{
	int fd = 0, nr = 0;

	while (fd < fda->nr) {
		if ((fda->entries[fd].revents & revents_and_mask) == 0)
			++nr;

		if (++fd != nr)
			fda->entries[nr] = fda->entries[fd];
	}

	fda->nr = nr;
	return nr;
}

int fdarray__poll(struct fdarray *fda, int timeout)
{
	return poll(fda->entries, fda->nr, timeout);
}

int fdarray__fprintf(struct fdarray *fda, FILE *fp)
{
	int fd, printed = fprintf(fp, "%d [ ", fda->nr);

	for (fd = 0; fd < fda->nr; ++fd)
		printed += fprintf(fp, "%s%d", fd ? ", " : "", fda->entries[fd].fd);

	return printed + fprintf(fp, " ]");
}
