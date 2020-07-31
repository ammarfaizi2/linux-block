// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/kcmp.h>

#include "pidfd.h"
#include "../clone3/clone3_selftests.h"
#include "../kselftest_harness.h"

static int sys_waitid(int which, pid_t pid, int options)
{
	return syscall(__NR_waitid, which, pid, NULL, options, NULL);
}

pid_t create_child(int *parent_tid, unsigned flags)
{
	struct clone_args args = {
		.flags		= CLONE_PARENT_SETTID | flags,
		.exit_signal	= SIGCHLD,
		.parent_tid	= ptr_to_u64(parent_tid),
	};

	return sys_clone3(&args, sizeof(struct clone_args));
}

/*
 * reaper
 *   |
 *   V
 * child1
 *   |
 *   V
 * child2
 *   |
 *   V
 * child3
 */
TEST(autoreap_on_simple_reparent)
{
	pid_t pid, reaper;
	pid_t *child;
	int ev_fd;
	char sync = '0';
	uint64_t wait_val = 0;

	child = mmap(NULL, 3 * sizeof(pid_t), PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	EXPECT_NE(child, MAP_FAILED);

	ev_fd = eventfd(0, EFD_CLOEXEC);
	EXPECT_GE(ev_fd, 0);

	reaper = create_child((int *){0}, 0);
	EXPECT_GE(reaper, 0);

        if (reaper == 0) {
        	EXPECT_EQ(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
        	EXPECT_EQ(prctl(59, 1), 0);

        	/* First child. */
        	pid = create_child(&child[0], 0);
		EXPECT_GE(pid, 0);
        	if (pid == 0) {
        		/* Second child. */
			pid = create_child(&child[1], 0);
			EXPECT_GE(pid, 0);
			if (pid == 0) {
        			/* Third child. */
				pid = create_child(&child[2], 0);
				EXPECT_GE(pid, 0);
				if (pid == 0) {
        				pause();
        				_exit(EXIT_SUCCESS);
        			}

				++wait_val;
				EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
				EXPECT_EQ(sys_waitid(P_PID, child[2], WEXITED | __WALL), 0);
				_exit(EXIT_SUCCESS);
        		}

			++wait_val;
			EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
			EXPECT_EQ(sys_waitid(P_PID, child[1], WEXITED | __WALL), 0);
			_exit(EXIT_SUCCESS);
        	}

		++wait_val;
		EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
		EXPECT_EQ(sys_waitid(P_ALL, child[0], WEXITED | __WALL), 0);

		/*
		 * First child has been repareted to us but we're not
		 * interested in its exit status.
		 */
		EXPECT_NE(sys_waitid(P_PID, child[1], WEXITED), 0);
		EXPECT_EQ(errno, ECHILD);
        	_exit(EXIT_SUCCESS);
       }

       EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
       EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
       EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));

       /* Kill first child, causing the second child to be reparented. */
       EXPECT_EQ(kill(child[0], SIGKILL), 0);

       /* Kill third child. */
       EXPECT_EQ(kill(child[2], SIGKILL), 0);
       EXPECT_EQ(sys_waitid(P_PID, reaper, WEXITED), 0);
}

TEST(autoreap_on_reparent_with_zombie)
{
	pid_t pid, reaper;
	pid_t *child;
	int ev_fd;
	char sync = '0';
	uint64_t wait_val = 0;

	child = mmap(NULL, 3 * sizeof(pid_t), PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	EXPECT_NE(child, MAP_FAILED);

	ev_fd = eventfd(0, EFD_CLOEXEC);
	EXPECT_GE(ev_fd, 0);

	reaper = create_child((int *){0}, 0);
	EXPECT_GE(reaper, 0);

        if (reaper == 0) {
        	EXPECT_EQ(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
        	EXPECT_EQ(prctl(59, 1), 0);

        	/* First child. */
        	pid = create_child(&child[0], 0);
		EXPECT_GE(pid, 0);
        	if (pid == 0) {
        		/* Second child. */
			pid = create_child(&child[1], 0);
			EXPECT_GE(pid, 0);
			if (pid == 0) {
        			/* Third child. */
				pid = create_child(&child[2], 0);
				EXPECT_GE(pid, 0);
				if (pid == 0)
        				_exit(EXIT_SUCCESS);

				++wait_val;
				EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
				/* leave as zombie. */
				_exit(EXIT_SUCCESS);
        		}

			++wait_val;
			EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
			/* leave as zombie. */
			_exit(EXIT_SUCCESS);
        	}

		++wait_val;
		EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
		/* reap the first child, causing the zombies to be reparented to us. */
		EXPECT_EQ(sys_waitid(P_ALL, child[0], WEXITED | __WALL), 0);

		/*
		 * First child has been repareted to us but we're not
		 * interested in its exit status.
		 */
		EXPECT_NE(sys_waitid(P_ALL, -1, WEXITED), 0);
		EXPECT_EQ(errno, ECHILD);

		EXPECT_NE(kill(child[1], 0), 0);
		EXPECT_EQ(errno, ESRCH);

		EXPECT_NE(kill(child[2], 0), 0);
		EXPECT_EQ(errno, ESRCH);

        	_exit(EXIT_SUCCESS);
       }

       EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
       EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
       EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));

       /* Kill first child, causing the second child to be reparented. */
       EXPECT_EQ(sys_waitid(P_PID, reaper, WEXITED), 0);
}

TEST(double_reparent)
{
	pid_t pid, reaper;
	pid_t *child;
	int ev_fd;
	char sync = '0';
	uint64_t wait_val = 0;

	child = mmap(NULL, 4 * sizeof(pid_t), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	EXPECT_NE(child, MAP_FAILED);

	ev_fd = eventfd(0, EFD_CLOEXEC);
	EXPECT_GE(ev_fd, 0);

	reaper = create_child((int *){0}, 0);
	EXPECT_GE(reaper, 0);
	if (reaper == 0) {
		TH_LOG("reaper %d", getpid());

		/* first-level subreaper */
		EXPECT_EQ(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);

		/* first child */
		pid = create_child(&child[0], 0);
		EXPECT_GE(pid, 0);

		if (pid == 0) {
			TH_LOG("child[0] %d", getpid());

			/* second-level subreaper */
			EXPECT_EQ(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
			EXPECT_EQ(prctl(59, 1), 0);

			/* second child */
			pid = create_child(&child[1], 0);
			EXPECT_GE(pid, 0);
			if (pid == 0) {
				TH_LOG("child[1] %d", getpid());

				/* third child */
				pid = create_child(&child[2], 0);
				EXPECT_GE(pid, 0);
				if (pid == 0) {
					TH_LOG("child[2] %d", getpid());

					/* fourth child */
					pid = create_child(&child[3], 0);
					EXPECT_GE(pid, 0);
					if (pid == 0) {
						TH_LOG("child[3] %d", getpid());

						pause();
						_exit(EXIT_SUCCESS);
					}

					++wait_val;
					EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
					EXPECT_EQ(sys_waitid(P_PID, child[3], WEXITED | __WALL), 0);
					_exit(EXIT_SUCCESS);
				}

				++wait_val;
				EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
				EXPECT_EQ(sys_waitid(P_PID, child[2], WEXITED | __WALL), 0);
				_exit(EXIT_SUCCESS);
			}

			++wait_val;
			EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
			EXPECT_EQ(sys_waitid(P_ALL, child[1], WEXITED | __WALL), 0);
			_exit(EXIT_SUCCESS);
		}

		++wait_val;
		EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
		sleep(5);
		EXPECT_EQ(sys_waitid(P_PID, child[2], WEXITED), 0);
		TH_LOG("Reaped reparented child[2] %d", child[2]);

		EXPECT_EQ(sys_waitid(P_PID, child[1], WEXITED), 0);
		TH_LOG("Reaped reparented child[1] %d", child[1]);

		EXPECT_EQ(sys_waitid(P_PID, child[0], WEXITED), 0);
		TH_LOG("Reaped natural child[0] %d", child[0]);
		_exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));

	/* reparent child[2] to child[0] */
	EXPECT_EQ(kill(child[1], SIGKILL), 0);
	/* reparent child[2] to reaper */
	EXPECT_EQ(kill(child[0], SIGKILL), 0);
	EXPECT_EQ(kill(child[3], SIGKILL), 0);

	EXPECT_EQ(sys_waitid(P_PID, reaper, WEXITED), 0);
}

TEST(autoreap_double_reparent)
{
	pid_t pid, reaper;
	pid_t *child;
	int ev_fd;
	char sync = '0';
	uint64_t wait_val = 0;

	child = mmap(NULL, 4 * sizeof(pid_t), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	EXPECT_NE(child, MAP_FAILED);

	ev_fd = eventfd(0, EFD_CLOEXEC);
	EXPECT_GE(ev_fd, 0);

	reaper = create_child((int *){0}, 0);
	EXPECT_GE(reaper, 0);
	if (reaper == 0) {
		TH_LOG("reaper %d", getpid());

		/* first-level subreaper */
		EXPECT_EQ(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
		EXPECT_EQ(prctl(59, 1), 0);

		/* first child */
		pid = create_child(&child[0], 0);
		EXPECT_GE(pid, 0);

		if (pid == 0) {
			TH_LOG("child[0] %d", getpid());

			/* second-level subreaper */
			EXPECT_EQ(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
			EXPECT_EQ(prctl(59, 1), 0);

			/* second child */
			pid = create_child(&child[1], 0);
			EXPECT_GE(pid, 0);
			if (pid == 0) {
				TH_LOG("child[1] %d", getpid());

				/* third child */
				pid = create_child(&child[2], 0);
				EXPECT_GE(pid, 0);
				if (pid == 0) {
					TH_LOG("child[2] %d", getpid());

					/* fourth child */
					pid = create_child(&child[3], 0);
					EXPECT_GE(pid, 0);
					if (pid == 0) {
						TH_LOG("child[3] %d", getpid());

						pause();
						_exit(EXIT_SUCCESS);
					}

					++wait_val;
					EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
					EXPECT_EQ(sys_waitid(P_PID, child[3], WEXITED | __WALL), 0);
					_exit(EXIT_SUCCESS);
				}

				++wait_val;
				EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
				EXPECT_EQ(sys_waitid(P_PID, child[2], WEXITED | __WALL), 0);
				_exit(EXIT_SUCCESS);
			}

			++wait_val;
			EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
			EXPECT_EQ(sys_waitid(P_ALL, child[1], WEXITED | __WALL), 0);
			_exit(EXIT_SUCCESS);
		}

		++wait_val;
		EXPECT_EQ(write(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
		sleep(5);

		EXPECT_EQ(sys_waitid(P_PID, child[0], WEXITED), 0);
		TH_LOG("Reaped natural child[0] %d", child[0]);

		EXPECT_NE(sys_waitid(P_ALL, -1, WEXITED), 0);
		EXPECT_EQ(errno, ECHILD);
		_exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));
	EXPECT_EQ(read(ev_fd, &wait_val, sizeof(wait_val)), sizeof(wait_val));

	/* reparent child[2] to child[0] */
	EXPECT_EQ(kill(child[1], SIGKILL), 0);
	/* reparent child[2] to reaper */
	EXPECT_EQ(kill(child[0], SIGKILL), 0);
	EXPECT_EQ(kill(child[3], SIGKILL), 0);

	EXPECT_EQ(sys_waitid(P_PID, reaper, WEXITED), 0);
}

TEST_HARNESS_MAIN
