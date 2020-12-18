// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "../clone3/clone3_selftests.h"

#ifndef __NR_close_range
	#if defined __alpha__
		#define __NR_close_range 546
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_close_range (436 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_close_range (436 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_close_range (436 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_close_range (436 + 1024)
	#else
		#define __NR_close_range 436
	#endif
#endif

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE	(1U << 1)
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC	(1U << 2)
#endif

static inline int sys_close_range(unsigned int fd, unsigned int max_fd,
				  unsigned int flags)
{
	return syscall(__NR_close_range, fd, max_fd, flags);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

TEST(close_range)
{
	int i, ret;
	int open_fds[101];

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	EXPECT_EQ(-1, sys_close_range(open_fds[0], open_fds[100], -1)) {
		if (errno == ENOSYS)
			SKIP(return, "close_range() syscall not supported");
	}

	EXPECT_EQ(0, sys_close_range(open_fds[0], open_fds[50], 0));

	for (i = 0; i <= 50; i++)
		EXPECT_EQ(-1, fcntl(open_fds[i], F_GETFL));

	for (i = 51; i <= 100; i++)
		EXPECT_GT(fcntl(open_fds[i], F_GETFL), -1);

	/* create a couple of gaps */
	close(57);
	close(78);
	close(81);
	close(82);
	close(84);
	close(90);

	EXPECT_EQ(0, sys_close_range(open_fds[51], open_fds[92], 0));

	for (i = 51; i <= 92; i++)
		EXPECT_EQ(-1, fcntl(open_fds[i], F_GETFL));

	for (i = 93; i <= 100; i++)
		EXPECT_GT(fcntl(open_fds[i], F_GETFL), -1);

	/* test that the kernel caps and still closes all fds */
	EXPECT_EQ(0, sys_close_range(open_fds[93], open_fds[99], 0));

	for (i = 93; i <= 99; i++)
		EXPECT_EQ(-1, fcntl(open_fds[i], F_GETFL));

	EXPECT_GT(fcntl(open_fds[i], F_GETFL), -1);

	EXPECT_EQ(0, sys_close_range(open_fds[100], open_fds[100], 0));

	EXPECT_EQ(-1, fcntl(open_fds[100], F_GETFL));
}

TEST(close_range_unshare)
{
	int i, ret, status;
	pid_t pid;
	int open_fds[101];
	struct __clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		ret = sys_close_range(open_fds[0], open_fds[50],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 0; i <= 50; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		for (i = 51; i <= 100; i++)
			if (fcntl(open_fds[i], F_GETFL) == -1)
				exit(EXIT_FAILURE);

		/* create a couple of gaps */
		close(57);
		close(78);
		close(81);
		close(82);
		close(84);
		close(90);

		ret = sys_close_range(open_fds[51], open_fds[92],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 51; i <= 92; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		for (i = 93; i <= 100; i++)
			if (fcntl(open_fds[i], F_GETFL) == -1)
				exit(EXIT_FAILURE);

		/* test that the kernel caps and still closes all fds */
		ret = sys_close_range(open_fds[93], open_fds[99],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 93; i <= 99; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		if (fcntl(open_fds[100], F_GETFL) == -1)
			exit(EXIT_FAILURE);

		ret = sys_close_range(open_fds[100], open_fds[100],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		if (fcntl(open_fds[100], F_GETFL) != -1)
			exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(true, WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST(close_range_unshare_capped)
{
	int i, ret, status;
	pid_t pid;
	int open_fds[101];
	struct __clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		ret = sys_close_range(open_fds[0], UINT_MAX,
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 0; i <= 100; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(true, WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST(close_range_cloexec)
{
	int i, ret;
	int open_fds[101];
	struct rlimit rlimit;

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	ret = sys_close_range(1000, 1000, CLOSE_RANGE_CLOEXEC);
	if (ret < 0) {
		if (errno == ENOSYS)
			SKIP(return, "close_range() syscall not supported");
		if (errno == EINVAL)
			SKIP(return, "close_range() doesn't support CLOSE_RANGE_CLOEXEC");
	}

	/* Ensure the FD_CLOEXEC bit is set also with a resource limit in place.  */
	ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &rlimit));
	rlimit.rlim_cur = 25;
	ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &rlimit));

	/* Set close-on-exec for two ranges: [0-50] and [75-100].  */
	ret = sys_close_range(open_fds[0], open_fds[50], CLOSE_RANGE_CLOEXEC);
	ASSERT_EQ(0, ret);
	ret = sys_close_range(open_fds[75], open_fds[100], CLOSE_RANGE_CLOEXEC);
	ASSERT_EQ(0, ret);

	for (i = 0; i <= 50; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}

	for (i = 51; i <= 74; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, 0);
	}

	for (i = 75; i <= 100; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}

	/* Test a common pattern.  */
	ret = sys_close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC);
	for (i = 0; i <= 100; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}
}

TEST(close_range_cloexec_unshare)
{
	int i, ret;
	int open_fds[101];
	struct rlimit rlimit;

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	ret = sys_close_range(1000, 1000, CLOSE_RANGE_CLOEXEC);
	if (ret < 0) {
		if (errno == ENOSYS)
			SKIP(return, "close_range() syscall not supported");
		if (errno == EINVAL)
			SKIP(return, "close_range() doesn't support CLOSE_RANGE_CLOEXEC");
	}

	/* Ensure the FD_CLOEXEC bit is set also with a resource limit in place.  */
	ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &rlimit));
	rlimit.rlim_cur = 25;
	ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &rlimit));

	/* Set close-on-exec for two ranges: [0-50] and [75-100].  */
	ret = sys_close_range(open_fds[0], open_fds[50],
			      CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE);
	ASSERT_EQ(0, ret);
	ret = sys_close_range(open_fds[75], open_fds[100],
			      CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE);
	ASSERT_EQ(0, ret);

	for (i = 0; i <= 50; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}

	for (i = 51; i <= 74; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, 0);
	}

	for (i = 75; i <= 100; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}

	/* Test a common pattern.  */
	ret = sys_close_range(3, UINT_MAX,
			      CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE);
	for (i = 0; i <= 100; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}
}

static uint64_t current_time_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		exit(EXIT_FAILURE);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void thread_start(void *(*fn)(void *), void *arg)
{
	int i;
	pthread_t th;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 128 << 10);

	for (i = 0; i < 100; i++) {
		if (pthread_create(&th, &attr, fn, arg) == 0) {
			pthread_attr_destroy(&attr);
			return;
		}

		if (errno == EAGAIN) {
			usleep(50);
			continue;
		}

		break;
	}

	exit(EXIT_FAILURE);
}

static void event_init(int *state)
{
	*state = 0;
}

static void event_reset(int *state)
{
	*state = 0;
}

static void event_set(int *state)
{
	if (*state)
		exit(EXIT_FAILURE);

	__atomic_store_n(state, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, state, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1000000);
}

static void event_wait(int *state)
{
	while (!__atomic_load_n(state, __ATOMIC_ACQUIRE))
		syscall(SYS_futex, state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0);
}

static int event_isset(int *state)
{
	return __atomic_load_n(state, __ATOMIC_ACQUIRE);
}

static int event_timedwait(int *state, uint64_t timeout)
{
	uint64_t start = current_time_ms();
	uint64_t now = start;
	for (;;) {
		struct timespec ts;
		uint64_t remain = timeout - (now - start);

		ts.tv_sec = remain / 1000;
		ts.tv_nsec = (remain % 1000) * 1000 * 1000;

		syscall(SYS_futex, state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &ts);

		if (__atomic_load_n(state, __ATOMIC_ACQUIRE))
			return 1;

		now = current_time_ms();
		if (now - start > timeout)
			return 0;
	}
}

struct thread_t {
	int created;
	int call;
	int ready;
	int done;
};

static struct thread_t threads[4];
static int running;

static void thread_close_range_call(int call)
{
	int fd = 0;

	switch (call) {
	case 0:
		fd = openat(-1, "/dev/null", 0, 0);
		if (fd < 0)
			fd = 0;
		break;
	case 1:
		sys_close_range(fd, -1, CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC);
		break;
	}
}

static void *thread_close_range(void *arg)
{
	struct thread_t *th = (struct thread_t *)arg;
	for (;;) {
		event_wait(&th->ready);
		event_reset(&th->ready);
		thread_close_range_call(th->call);
		__atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
		event_set(&th->done);
	}
	return 0;
}

static void threaded_close_range(void)
{
	int i, fd, call, thread;
	for (call = 0; call < 2; call++) {
		for (thread = 0; thread < (int)(sizeof(threads) / sizeof(threads[0])); thread++) {
			struct thread_t *th = &threads[thread];
			if (!th->created) {
				th->created = 1;
				event_init(&th->ready);
				event_init(&th->done);
				event_set(&th->done);
				thread_start(thread_close_range, th);
			}

			if (!event_isset(&th->done))
				continue;

			event_reset(&th->done);
			th->call = call;
			__atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
			event_set(&th->ready);
			event_timedwait(&th->done, 45);
			break;
		}
	}

	for (i = 0; i < 100 && __atomic_load_n(&running, __ATOMIC_RELAXED); i++)
		usleep(1000);

	for (fd = 3; fd < 30; fd++)
		close(fd);
}

/*
 * Regression test for syzbot+96cfd2b22b3213646a93@syzkaller.appspotmail.com
 */
TEST(close_range_cloexec_unshare_threaded_syzbot)
{
	int iter;
	int fd1, fd2, fd3;

	/*
	 * Create a huge gap in the fd table. When we now call
	 * CLOSE_RANGE_UNSHARE with a shared fd table and and with ~0U as upper
	 * bound the kernel will only copy up to fd1 file descriptors into the
	 * new fd table. If max_fd in the close_range() codepaths isn't
	 * correctly set when requesting CLOSE_RANGE_CLOEXEC with all of these
	 * fds we will see NULL pointer derefs!
	 */
	fd1 = open("/dev/null", O_RDWR);
	EXPECT_GT(fd1, 0);

	fd3 = dup2(fd1, 1000);
	EXPECT_GT(fd3, 0);

	for (iter = 0; iter <= 1000; iter++) {
		pid_t pid;
		int status;
		uint64_t start;

		pid = fork();
		if (pid < 0)
			exit(EXIT_FAILURE);
		if (pid == 0) {
			EXPECT_EQ(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0), 0);
			setpgrp();

			threaded_close_range();
			exit(EXIT_SUCCESS);
		}

		status = 0;
		start = current_time_ms();
		for (;;) {
			if (waitpid(-1, &status, WNOHANG | __WALL) == pid)
				break;

			usleep(1000);

			if (current_time_ms() - start < 5 * 1000)
				continue;

			kill(pid, SIGKILL);

			EXPECT_EQ(waitpid(pid, &status, 0), pid);

			EXPECT_EQ(true, WIFEXITED(status));

			EXPECT_EQ(0, WEXITSTATUS(status));
		}
	}
}

TEST_HARNESS_MAIN
