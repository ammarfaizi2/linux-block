#ifndef __API_FD_POLL__
#define __API_FD_POLL__

#include <stdio.h>

struct pollfd;

struct fdarray {
	int	       nr;
	int	       nr_alloc;
	struct pollfd *entries;
};

void fdarray__init(struct fdarray *fda);
void fdarray__exit(struct fdarray *fda);

struct fdarray *fdarray__new(int nr_alloc);
void fdarray__delete(struct fdarray *fda);

int fdarray__add(struct fdarray *fda, int fd);
int fdarray__poll(struct fdarray *fda, int timeout);
int fdarray__filter(struct fdarray *fda, short revents_and_mask);
int fdarray__grow(struct fdarray *fda, int extra);
int fdarray__fprintf(struct fdarray *fda, FILE *fp);

static inline int fdarray__available_entries(struct fdarray *fda)
{
	return fda->nr_alloc - fda->nr;
}

#endif /* __API_FD_POLL__ */
