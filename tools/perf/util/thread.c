#include "../perf.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "session.h"
#include "thread.h"
#include "util.h"
#include "debug.h"
#include "comm.h"

struct thread *thread__new(pid_t pid, pid_t tid)
{
	char *comm_str;
	struct comm *comm;
	struct thread *self = zalloc(sizeof(*self));

	if (self != NULL) {
		map_groups__init(&self->mg);
		self->pid_ = pid;
		self->tid = tid;
		self->ppid = -1;
		INIT_LIST_HEAD(&self->comm_list);

		comm_str = malloc(32);
		if (!comm_str)
			goto err_thread;

		snprintf(comm_str, 32, ":%d", tid);
		comm = comm__new(comm_str, 0);
		free(comm_str);
		if (!comm)
			goto err_thread;

		list_add(&comm->list, &self->comm_list);
	}

	return self;

err_thread:
	free(self);
	return NULL;
}

void thread__delete(struct thread *self)
{
	struct comm *comm, *tmp;

	map_groups__exit(&self->mg);
	list_for_each_entry_safe(comm, tmp, &self->comm_list, list) {
		list_del(&comm->list);
		comm__free(comm);
	}

	free(self);
}

struct comm *curr_comm(const struct thread *thread)
{
	if (list_empty(&thread->comm_list))
		return NULL;

	return list_first_entry(&thread->comm_list, struct comm, list);
}

/* CHECKME: time should always be 0 if event aren't ordered */
int thread__set_comm(struct thread *thread, const char *str, u64 timestamp)
{
	struct comm *new, *curr = curr_comm(thread);

	/* Override latest entry if it had no specific time coverage */
	if (!curr->start) {
		comm__override(curr, str, timestamp);
		return 0;
	}

	new = comm__new(str, timestamp);
	if (!new)
		return -ENOMEM;

	list_add(&new->list, &thread->comm_list);
	thread->comm_set = true;

	return 0;
}

const char *thread__comm_curr(const struct thread *thread)
{
	const struct comm *comm = curr_comm(thread);

	if (!comm)
		return NULL;

	return comm__str(comm);
}

/* CHECKME: it should probably better return the max comm len from its comm list */
int thread__comm_len(struct thread *self)
{
	if (!self->comm_len) {
		const char *comm = thread__comm_curr(self);
		if (!comm)
			return 0;
		self->comm_len = strlen(comm);
	}

	return self->comm_len;
}

size_t thread__fprintf(struct thread *thread, FILE *fp)
{
	return fprintf(fp, "Thread %d %s\n", thread->tid, thread__comm_curr(thread)) +
	       map_groups__fprintf(&thread->mg, verbose, fp);
}

void thread__insert_map(struct thread *self, struct map *map)
{
	map_groups__fixup_overlappings(&self->mg, map, verbose, stderr);
	map_groups__insert(&self->mg, map);
}

int thread__fork(struct thread *thread, struct thread *parent, u64 timestamp)
{
	int i, err;

	if (parent->comm_set) {
		const char *comm = thread__comm_curr(parent);
		if (!comm)
			return -ENOMEM;
		err = thread__set_comm(thread, comm, timestamp);
		if (!err)
			return err;
		thread->comm_set = true;
	}

	for (i = 0; i < MAP__NR_TYPES; ++i)
		if (map_groups__clone(&thread->mg, &parent->mg, i) < 0)
			return -ENOMEM;

	thread->ppid = parent->tid;

	return 0;
}
