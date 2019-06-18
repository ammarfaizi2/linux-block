// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2018	Roman Penyaev
 *  Copyright (C) 2019	David Howells <dhowells@redhat.com>
 *
 *  Purpose of the tool is to generate N events from different threads and to
 *  measure how fast those events will be delivered to thread which does epoll.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <err.h>
#include <numa.h>
#include <poll.h>
#include <linux/unistd.h>
#include <linux/watch_queue.h>
#define epoll_event xxx_epoll_event
#include <linux/eventpoll.h>
#undef epoll_event
#undef EPOLL_CLOEXEC
#undef EPOLLIN
#undef EPOLLPRI
#undef EPOLLOUT
#undef EPOLLERR
#undef EPOLLHUP
#undef EPOLLNVAL
#undef EPOLLRDNORM
#undef EPOLLRDBAND
#undef EPOLLWRNORM
#undef EPOLLWRBAND
#undef EPOLLMSG
#undef EPOLLRDHUP
#undef EPOLLEXCLUSIVE
#undef EPOLLWAKEUP
#undef EPOLLONESHOT
#undef EPOLLET

#include <sys/epoll.h>

#define BUILD_BUG_ON(condition) ((void )sizeof(char [1 - 2*!!(condition)]))
#define READ_ONCE(v) __atomic_load(&v, __ATOMIC_RELAXED)

#define ITERS	  1000000ull

#ifndef __NR_epoll_create2
#define __NR_epoll_create2 -1
#endif

static inline long epoll_create2(int flags, size_t size, int watch_fd)
{
	return syscall(__NR_epoll_create2, flags, size, watch_fd);
}

struct thread_ctx {
	pthread_t thread;
	int efd;
};

struct cpu_map {
	unsigned int nr;
	unsigned int map[];
};

static volatile unsigned int thr_ready;
static volatile unsigned int start;

static int is_cpu_online(int cpu)
{
	char buf[64];
	char online;
	FILE *f;
	int rc;

	snprintf(buf, sizeof(buf), "/sys/devices/system/cpu/cpu%d/online", cpu);
	f = fopen(buf, "r");
	if (!f)
		return 1;

	rc = fread(&online, 1, 1, f);
	assert(rc == 1);
	fclose(f);

	return (char)online == '1';
}

static struct cpu_map *cpu_map__new(void)
{
	struct cpu_map *cpu;
	struct bitmask *bm;

	int i, bit, cpus_nr;

	cpus_nr = numa_num_possible_cpus();
	cpu = calloc(1, sizeof(*cpu) + sizeof(cpu->map[0]) * cpus_nr);
	if (!cpu)
		return NULL;

	bm = numa_all_cpus_ptr;
	assert(bm);

	for (bit = 0, i = 0; bit < bm->size; bit++) {
		if (numa_bitmask_isbitset(bm, bit) && is_cpu_online(bit)) {
			cpu->map[i++] = bit;
		}
	}
	cpu->nr = i;

	return cpu;
}

static void cpu_map__put(struct cpu_map *cpu)
{
	free(cpu);
}

static inline unsigned long long nsecs(void)
{
	struct timespec ts = {0, 0};

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((unsigned long long)ts.tv_sec * 1000000000ull) + ts.tv_nsec;
}

static void *thread_work(void *arg)
{
	struct thread_ctx *ctx = arg;
	__u64 ucnt = 1;
	unsigned int i;
	int rc;

	__atomic_add_fetch(&thr_ready, 1, __ATOMIC_RELAXED);

	while (!start)
		;

	for (i = 0; i < ITERS; i++) {
		rc = write(ctx->efd, &ucnt, sizeof(ucnt));
		assert(rc == sizeof(ucnt));
	}

	return NULL;
}

/*
 * Process an event.
 */
static __attribute__((noinline))
void read_event(struct epoll_uheader *header, unsigned int idx,
		struct epoll_event *event)
{
	struct epoll_uitem *item = &header->items[idx];

	assert(idx <= header->max_items_nr); /* Corrupted index? */

	/*
	 * Fetch data first, if event is cleared by the kernel we drop the data
	 * returning false.
	 */
	event->data.u64	= item->data;
	event->events	= __atomic_exchange_n(&item->ready_events, 0,
					      __ATOMIC_RELEASE);
	
	assert(event->events & ~EPOLLREMOVED);
}

/*
 * Consume watch notifications, looking for EPOLL events.
 */
static int watch_queue_consumer(int wfd, struct watch_queue_buffer *buf,
				struct epoll_uheader *header,
				struct epoll_event *events,
				bool can_sleep)
{
	struct watch_notification *n;
	struct epoll_notification *en;
	unsigned int len, head, tail, mask = buf->meta.mask;
	unsigned int epoll_slot;
	int nfds = 0;

	/* 'tail' belongs to us and is where events are consumed from */
	tail = buf->meta.tail;

	/* 'head' belongs to the kernel and is where events are inserted. */
	if (can_sleep) {
		head = __atomic_load_n(&buf->meta.head, __ATOMIC_ACQUIRE);
		if (tail == head) {
			struct pollfd p[1];
			p[0].fd = wfd;
			p[0].events = POLLIN | POLLERR;
			p[0].revents = 0;

			if (poll(p, 1, -1) == -1)
				err(EXIT_FAILURE, "wq/poll");
		}
	}

#if 0
	printf("ptrs h=%x t=%x m=%x\n",
	       buf->meta.head, buf->meta.tail, buf->meta.mask);
#endif

	head = __atomic_load_n(&buf->meta.head, __ATOMIC_ACQUIRE);
	while (tail != head) {
		n = &buf->slots[tail & mask];
#if 0
		printf("NOTIFY[%08x-%08x] ty=%04x sy=%04x i=%08x\n",
		       head, tail, n->type, n->subtype, n->info);
#endif
		if (buf->meta.watch.info & WATCH_INFO_NOTIFICATIONS_LOST)
			printf("[!] notifications lost\n");

		len = (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;
		assert(len > 0);

		switch (n->type) {
		case WATCH_TYPE_META:
#if 0
			if (n->subtype == WATCH_META_REMOVAL_NOTIFICATION)
				printf("REMOVAL of watchpoint %08x\n",
				       n->info & WATCH_INFO_ID);
#endif
			/* Fall through */
		default:
			tail += len;
			__atomic_store_n(&buf->meta.tail, tail, __ATOMIC_RELEASE);
			break;

		case WATCH_TYPE_EPOLL_NOTIFY:
			en = (struct epoll_notification *)n;
			epoll_slot = en->watch.info & WATCH_INFO_TYPE_INFO;
			epoll_slot >>= WATCH_INFO_TYPE_INFO__SHIFT;

			/* Consume the slot before we clear the events */
			tail += len;
			__atomic_store_n(&buf->meta.tail, tail, __ATOMIC_RELEASE);

			read_event(header, epoll_slot, &events[nfds]);
			nfds++;
			break;
		}
	}

	return nfds;
}

/*
 * Map the epoll descriptor table into the kernel.
 */
static void uepoll_mmap(int epfd, struct epoll_uheader **_header, size_t *_mapping_size)
{
	struct epoll_uheader *header;
	unsigned int len;

	BUILD_BUG_ON(sizeof(*header) != EPOLL_USERPOLL_HEADER_SIZE);
	BUILD_BUG_ON(sizeof(header->items[0]) != 16);

	len = sysconf(_SC_PAGESIZE);
again:
	header = mmap(NULL, len, PROT_WRITE|PROT_READ, MAP_SHARED, epfd, 0);
	if (header == MAP_FAILED)
		err(EXIT_FAILURE, "mmap(header)");

	if (header->header_length != len) {
		unsigned int tmp_len = len;

		len = header->header_length;
		munmap(header, tmp_len);
		goto again;
	}

	assert(header->magic == EPOLL_USERPOLL_HEADER_MAGIC);
	*_header = header;
	*_mapping_size = len;
}

/*
 * Create a watch queue and map it.
 */
static int create_watch_queue(unsigned int buffer_size,
			      struct watch_queue_buffer **_watch_queue)
{
	struct watch_queue_buffer *buf;
	size_t page_size;
	int wfd;

	wfd = open("/dev/watch_queue", O_RDWR);
	if (wfd == -1)
		err(EXIT_FAILURE, "/dev/watch_queue");

	if (ioctl(wfd, IOC_WATCH_QUEUE_SET_SIZE, buffer_size) == -1)
		err(EXIT_FAILURE, "wq/size");

	page_size = sysconf(_SC_PAGESIZE);
	buf = mmap(NULL, buffer_size * page_size,
		   PROT_READ | PROT_WRITE, MAP_SHARED, wfd, 0);
	if (buf == MAP_FAILED)
		err(EXIT_FAILURE, "wq/mmap");

	*_watch_queue = buf;
	return wfd;
}

static int do_bench(struct cpu_map *cpu, unsigned int nthreads,
		    int wfd, struct watch_queue_buffer *watch_queue)
{
	struct epoll_event ev, events[nthreads];
	struct thread_ctx threads[nthreads];
	pthread_attr_t thrattr;
	struct thread_ctx *ctx;
	size_t mapping_size;
	int rc, epfd, nfds;
	cpu_set_t cpuset;
	unsigned int i;

	struct epoll_uheader *header;

	unsigned long long epoll_calls = 0, epoll_nsecs;
	unsigned long long ucnt, ucnt_sum = 0;

	thr_ready = 0;
	start = 0;

	epfd = epoll_create2(EPOLL_USERPOLL, nthreads, wfd);
	if (epfd < 0)
		err(EXIT_FAILURE, "epoll_create2");

	for (i = 0; i < nthreads; i++) {
		ctx = &threads[i];

		ctx->efd = eventfd(0, EFD_NONBLOCK);
		if (ctx->efd < 0)
			err(EXIT_FAILURE, "eventfd");

		ev.events = EPOLLIN | EPOLLET;
		ev.data.ptr = ctx;
		rc = epoll_ctl(epfd, EPOLL_CTL_ADD, ctx->efd, &ev);
		if (rc)
			err(EXIT_FAILURE, "epoll_ctl");

		CPU_ZERO(&cpuset);
		CPU_SET(cpu->map[i % cpu->nr], &cpuset);

		pthread_attr_init(&thrattr);
		rc = pthread_attr_setaffinity_np(&thrattr, sizeof(cpu_set_t),
						 &cpuset);
		if (rc) {
			errno = rc;
			err(EXIT_FAILURE, "pthread_attr_setaffinity_np");
		}

		rc = pthread_create(&ctx->thread, NULL, thread_work, ctx);
		if (rc) {
			errno = rc;
			err(EXIT_FAILURE, "pthread_create");
		}
	}

	/* Map all pointers */
	uepoll_mmap(epfd, &header, &mapping_size);

	while (thr_ready != nthreads)
		;

	watch_queue_consumer(wfd, watch_queue, header, events, false);
	
	/* Signal start for all threads */
	start = 1;

	epoll_nsecs = nsecs();
	while (1) {
		nfds = watch_queue_consumer(wfd, watch_queue, header, events,
					    true);
		if (nfds < 0)
			err(EXIT_FAILURE, "epoll_wait");

		epoll_calls++;

		for (i = 0; i < (unsigned int)nfds; ++i) {
			ctx = events[i].data.ptr;
			rc = read(ctx->efd, &ucnt, sizeof(ucnt));
			if (rc < 0) {
				assert(errno == EAGAIN);
				continue;
			}
			assert(rc == sizeof(ucnt));
			ucnt_sum += ucnt;
			if (ucnt_sum == nthreads * ITERS)
				goto end;
		}
	}
end:
	epoll_nsecs = nsecs() - epoll_nsecs;

	for (i = 0; i < nthreads; i++) {
		ctx = &threads[i];
		pthread_join(ctx->thread, NULL);
	}

	close(epfd);

	watch_queue_consumer(wfd, watch_queue, header, events, false);
	munmap(header, mapping_size);

	printf("%7d   %8lld	%8lld\n",
	       nthreads,
	       ITERS * nthreads / (epoll_nsecs / 1000 / 1000),
	       epoll_nsecs / 1000 / 1000);

	return 0;
}

int main(int argc, char *argv[])
{
	static const unsigned int nthreads_arr[] = { 1, 8, 16, 32, 64, 128, 256 };
	struct watch_queue_buffer *watch_queue;
	struct cpu_map *cpu;
	unsigned int i;
	int wfd;

	wfd = create_watch_queue(1, &watch_queue);

	cpu = cpu_map__new();
	if (!cpu) {
		errno = ENOMEM;
		err(EXIT_FAILURE, "cpu_map__new");
	}

	printf("threads	 events/ms  run-time ms\n");
	for (i = 0; i < sizeof(nthreads_arr) / sizeof(nthreads_arr[0]); i++)
		do_bench(cpu, nthreads_arr[i], wfd, watch_queue);

	cpu_map__put(cpu);

	return 0;
}
