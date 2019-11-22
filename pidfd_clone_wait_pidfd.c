/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

#ifndef CLONE_WAIT_PIDFD
#define CLONE_WAIT_PIDFD 0x200000000ULL
#endif

#ifndef __NR_clone3
#define __NR_clone3 -1
#endif

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal -1
#endif

#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

sigjmp_buf mark;

static pid_t sys_clone3(struct clone_args *args)
{
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

static pid_t sys_pidfd_send_signal(int pidfd, int signal)
{
	return syscall(__NR_pidfd_send_signal, pidfd, signal, NULL, 0);
}

/*
 * Test that a child process created with the CLONE_WAIT_PIDFD property is
 * autoreaped on process exit if the child is exiting _after_ the last pidfd
 * has been closed.
 */
static void test_parent_close_last_pidfd_before_exit(void)
{
	int pidfd = -1;
	struct clone_args args = {
		.pidfd = ptr_to_u64(&pidfd),

		/*
		 * Create process as CLONE_VFORK to suspend parent execution
		 * until the child has exited. This ensure that the parent sees
		 * the child in EXIT_ZOMBIE state.
		 */
		.flags = CLONE_PIDFD | CLONE_WAIT_PIDFD,
		.exit_signal = SIGCHLD,
	};
	siginfo_t info = {
		.si_signo = 0,
	};
	int ret;
	int block_child[2], block_parent[2];
	pid_t pid;

	printf("Calling function %s in process %d\n", __FUNCTION__, getpid());

	ret = pipe2(block_child, O_CLOEXEC);
	if (ret) {
		printf("FAIL: Failed to create child block pipe\n");
		exit(EXIT_SUCCESS);
	}

	ret = pipe2(block_parent, O_CLOEXEC);
	if (ret) {
		printf("FAIL: Failed to create parent block pipe\n");
		exit(EXIT_SUCCESS);
	}

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("FAIL: Failed to create new process\n");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		printf("Child with pid %d\n", getpid());

		close(block_child[1]);
		close(block_parent[0]);
		ret = read(block_child[0], (char *){0}, 1);
		if (ret)
			printf("SUCC: Parent told us to proceed\n");

		printf("SUCC: Child process with pid %d\n", getpid());
		sleep(2);
		_exit(EXIT_SUCCESS);
	}

	/* Process should now be autoreaped after close() returns. */
	ret = close(pidfd);
	if (ret) {
		printf("FAIL: Failed to close pidfd %d for process %d\n", pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: Closed last pidfd %d for process %d\n", pidfd, pid);

	ret = write(block_child[1], "0", 1);
	if (ret)
		printf("SUCC: Told child to proceed\n");
	close(block_child[0]);
	close(block_parent[1]);

	ret = waitid(P_PID, pid, &info, WEXITED | WSTOPPED | __WALL);
	if (ret == 0) {
		printf("FAIL: Managed to wait on process %d via P_PID after closing last pidfd\n", pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: %s - Failed to wait on process %d via P_PID after closing last pidfd\n", strerror(errno), pid);

	ret = read(block_parent[0], (char *){0}, 1);
	if (ret)
		printf("SUCC: Child exited\n");
	close(block_parent[0]);
}

static void test_parent_close_last_pidfd_before_exit_ptrace(void)
{
	int pidfd = -1;
	struct clone_args args = {
		.pidfd = ptr_to_u64(&pidfd),

		/*
		 * Create process as CLONE_VFORK to suspend parent execution
		 * until the child has exited. This ensure that the parent sees
		 * the child in EXIT_ZOMBIE state.
		 */
		.flags = CLONE_PIDFD | CLONE_WAIT_PIDFD,
		.exit_signal = SIGCHLD,
	};
	siginfo_t info = {
		.si_signo = 0,
	};
	int ret;
	int block_parent[2];
	pid_t pid;

	printf("Calling function %s in process %d\n", __FUNCTION__, getpid());

	ret = pipe2(block_parent, O_CLOEXEC);
	if (ret) {
		printf("Failed to create child block pipe\n");
		exit(EXIT_SUCCESS);
	}

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("Faild to create new process\n");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		pid_t child;

		child = getpid();
		printf("Child with pid %d\n", child);

		ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (ret) {
			printf("FAIL: Make parent trace us %d\n", child);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC: Made parent trace us %d\n", child);

		/* Tell parent to proceed since we're ptraced now. */
		close(block_parent[0]);
		ret = write(block_parent[1], "0", 1);
		if (ret)
			printf("Told parent to proceed\n");

		ret = raise(SIGSTOP);
		if (ret) {
			printf("FAIL: Raise SIGSTOP signal for pid %d\n", child);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC: Raised SIGSTOP signal for %d\n", child);

		printf("Child process with pid %d\n", getpid());
		_exit(EXIT_SUCCESS);
	}

	/* Process should now be autoreaped after close() returns. */
	ret = close(pidfd);
	if (ret) {
		printf("FAIL: Failed to close pidfd %d for process %d\n", pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: Closed last pidfd %d for process %d\n", pidfd, pid);

	/* Wait until child has started being ptraced. */
	close(block_parent[1]);
	ret = read(block_parent[0], (char *){0}, 1);
	if (ret)
		printf("SUCC: Child told us to proceed\n");

	/*
	 * Now we're sure that we're tracing the child so we need to be able to
	 * wait on it even if CLONE_WAIT_PIDFD is set.
	 */
	ret = waitid(P_PID, pid, &info, WSTOPPED | __WALL);
	if (ret) {
		printf("FAIL: %s - Failed to wait on process %d via P_PID after closing last pidfd\n", strerror(errno), pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: Managed to wait on process %d via P_PID after closing last pidfd\n", pid);

	ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (ret) {
		printf("FAIL: %s - ptrace(PTRACE_DETACH) from child failed\n", strerror(errno));
		_exit(EXIT_FAILURE);
	}
	printf("SUCC: ptrace(PTRACE_DETACH) from child succeeded\n");

	/*
	 * Has CLONE_WAIT_PIDFD and we're not ptracing our child anymore so
	 * this wait must fail.
	 */
	ret = waitid(P_PID, pid, &info, WEXITED | __WALL);
	if (ret == 0) {
		printf("FAIL: Managed to wait on process %d via P_PID after closing last pidfd\n", pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: %s - Failed to wait on process %d via P_PID after closing last pidfd\n", strerror(errno), pid);
}

/*
 * Test that a child process created with the CLONE_WAIT_PIDFD property in
 * EXIT_ZOMBIE state is autoreaped on process exit.
 */
static void test_parent_close_last_pidfd_after_exit(void)
{
	int pidfd = -1;
	struct clone_args args = {
		.pidfd = ptr_to_u64(&pidfd),

		/*
		 * Create process as CLONE_VFORK to suspend parent execution
		 * until the child has exited. This ensure that the parent sees
		 * the child in EXIT_ZOMBIE state.
		 */
		.flags = CLONE_PIDFD | CLONE_WAIT_PIDFD | CLONE_VFORK,
		.exit_signal = SIGCHLD,
	};
	int ret;
	pid_t pid;
	siginfo_t info = {
		.si_signo = 0,
	};

	printf("Calling function %s in process %d\n", __FUNCTION__, getpid());

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("FAIL: Failed to create new process\n");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		printf("SUCC: Child process with pid %d\n", getpid());
		_exit(EXIT_SUCCESS);
	}

	/*
	 * Note, parent execution is suspended until child exits due to
	 * CLONE_VFORK.
	 */
	ret = waitid(P_PID, pid, &info, WEXITED | __WALL);
	if (ret == 0) {
		printf("FAIL: Managed to wait on process %d via P_PID after closing last pidfd\n", pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: %s - Failed to wait on process %d via P_PID after closing last pidfd\n", strerror(errno), pid);

	/* Process should now be autoreaped after close() returns. */
	ret = close(pidfd);
	if (ret) {
		printf("FAIL: Failed to close pidfd %d for process %d\n", pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: Closed last pidfd %d for process %d\n", pidfd, pid);

	ret = waitid(P_PID, pid, &info, WEXITED | __WALL);
	if (ret == 0) {
		printf("FAIL: Managed to wait on process %d via P_PID after closing last pidfd\n", pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: %s - Failed to wait on process %d via P_PID after closing last pidfd\n", strerror(errno), pid);
}

/*
 * Test that a process created with the CLONE_WAIT_PIDFD property in
 * EXIT_ZOMBIE state is autoreaped on process exit by a non-parent process.
 */
static void test_stranger_close_last_pidfd_after_exit(void)
{
	int pidfd = -1;
	struct clone_args args = {
		.pidfd = ptr_to_u64(&pidfd),

		/*
		 * Create process as CLONE_VFORK to suspend parent execution
		 * until the child has exited. This ensure that the parent sees
		 * the child in EXIT_ZOMBIE state.
		 */
		.flags = CLONE_PIDFD | CLONE_WAIT_PIDFD | CLONE_VFORK,
		.exit_signal = SIGCHLD,
	};
	ssize_t ret;
	int block_child[2];
	pid_t pid;
	pid_t pid_sibling;
	siginfo_t info = {
		.si_signo = 0,
	};

	printf("Calling function %s in process %d\n", __FUNCTION__, getpid());

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("FAIL: Failed to create new process\n");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		printf("SUCC: Child process with pid %d\n", getpid());
		exit(EXIT_SUCCESS);
	}

	ret = pipe2(block_child, O_CLOEXEC);
	if (ret) {
		printf("FAIL: Failed to create pipe\n");
		exit(EXIT_SUCCESS);
	}

	pid_sibling = fork();
	if (pid_sibling < 0) {
		printf("FAIL: Failed to create second process\n");
		exit(EXIT_FAILURE);
	}

	if (pid_sibling == 0) {
		close(block_child[1]);
		ret = read(block_child[0], (char *){0}, 1);
		if (ret)
			printf("SUCC: Parent told us to proceed\n");

		/* This close will reap the first child. */
		ret = close(pidfd);
		if (ret) {
			printf("FAIL: Failed to close pidfd %d for process %d in sibling\n", pidfd, pid);
			exit(EXIT_FAILURE);
		}
		printf("SUCC: Closed pidfd %d for process %d in child\n", pidfd, pid);

		exit(EXIT_SUCCESS);
	}

	ret = close(pidfd);
	if (ret) {
		printf("FAIL: Failed to close pidfd %d for process %d in parent\n", pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: Closed pidfd %d for process %d in parent\n", pidfd, pid);

	sleep(2);
	ret = write(block_child[1], "0", 1);
	if (ret)
		printf("SUCC: Told child to proceed\n");
	close(block_child[0]);

	ret = waitid(P_PID, pid_sibling, &info, WEXITED | __WALL);
	if (ret) {
		printf("FAIL: %s - Failed to wait on sibling process %d via P_PID after closing last pidfd\n", strerror(errno), pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: Managed to wait on sibling process %d via P_PID after closing last pidfd\n", pid);

	ret = waitid(P_PID, pid, &info, WEXITED | WSTOPPED | __WALL);
	if (ret == 0) {
		printf("FAIL: Managed to wait on process %d via P_PID after closing last pidfd\n", pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: %s - Failed to wait on process %d via P_PID after closing last pidfd\n", strerror(errno), pid);
}

static void test_no_wait_without_pidfd(void)
{
	int pidfd = -1;
	struct clone_args args = {
		.pidfd = ptr_to_u64(&pidfd),

		/*
		 * Create process as CLONE_VFORK to suspend parent execution
		 * until the child has exited. This ensure that the parent sees
		 * the child in EXIT_ZOMBIE state.
		 */
		.flags = CLONE_PIDFD | CLONE_WAIT_PIDFD,
		.exit_signal = SIGCHLD,
	};
	siginfo_t info = {
		.si_signo = 0,
	};
	int ret;
	pid_t pid;

	printf("Calling function %s in process %d\n", __FUNCTION__, getpid());

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("FAIL: Failed to create new process\n");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		printf("SUCC: Child process with pid %d\n", getpid());
		_exit(EXIT_SUCCESS);
	}

	/*
	 * CLONE_WAIT_PIDFD is set so we are not allowed to wait on this
	 * process.
	 */
	ret = waitid(P_PID, pid, &info, WEXITED | __WALL);
	if (ret == 0) {
		printf("FAIL: Managed to wait on process %d via P_PID after closing last pidfd\n", pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: %s - Failed to wait on process %d via P_PID after closing last pidfd\n", strerror(errno), pid);

	/* Process should now be autoreaped after close() returns. */
	ret = close(pidfd);
	if (ret) {
		printf("FAIL: Failed to close pidfd %d for process %d\n", pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC: Closed last pidfd %d for process %d\n", pidfd, pid);
}

static void test_ptrace_reparented_pidfd(void)
{
	int pidfd = -1;
	struct clone_args args = {
		.pidfd = ptr_to_u64(&pidfd),

		/*
		 * Create process as CLONE_VFORK to suspend parent execution
		 * until the child has exited. This ensure that the parent sees
		 * the child in EXIT_ZOMBIE state.
		 */
		.flags = CLONE_PIDFD | CLONE_WAIT_PIDFD,
		.exit_signal = SIGCHLD,
	};
	ssize_t ret;
	pid_t pid, self;
	pid_t pid_sibling;
	siginfo_t info = {
		.si_signo = 0,
	};

	self = getpid();
	printf("Calling function %s in process %d\n", __FUNCTION__, self);

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("FAIL(%d): Failed to create new process\n", self);
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		self = getpid();
		printf("SUCC(%d): Child process with pid %d\n", self, self);

		ret = raise(SIGSTOP);
		if (ret) {
			printf("FAIL(%d): Raise SIGSTOP signal for pid %d\n", self, self);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): Raised SIGSTOP signal for %d\n", self, self);
		exit(EXIT_SUCCESS);
	}

	/*
	 * We're not tracing the process and CLONE_WAIT_PIDFD is set so this
	 * must fail.
	 */
	ret = waitid(P_PID, pid, &info, WSTOPPED | __WALL);
	if (ret == 0) {
		printf("FAIL(%d): %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, ret, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %s - %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, strerror(errno), ret, pid);

	ret = waitid(P_PIDFD, pidfd, &info, WSTOPPED | __WALL);
	if (ret) {
		printf("FAIL(%d): %s - %zd = waitid(P_PIDFD, %d->%d, &info, WSTOPPED | __WALL)\n", self, strerror(errno), ret, pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = waitid(P_PIDFD, %d->%d, &info, WSTOPPED | __WALL)\n", self, ret, pidfd, pid);

	/* Process is now stopped. */

	pid_sibling = fork();
	if (pid_sibling < 0) {
		printf("FAIL(%d): Failed to create second process\n", self);
		exit(EXIT_FAILURE);
	}

	if (pid_sibling == 0) {
		self = getpid();

		/*
		 * Trace a the non-child process pid. This means pid has now
		 * been reparented to us.
		 */
		ret = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
		if (ret) {
			printf("FAIL(%d): %s - %zd = ptrace(PTRACE_SEIZE, %d, NULL, NULL)\n", self, strerror(errno), ret, pid);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = ptrace(PTRACE_SEIZE, %d, NULL, NULL)\n", self, ret, pid);

		ret = sys_pidfd_send_signal(pidfd, SIGCONT);
		if (ret) {
			printf("FAIL(%d): %s - %zd = sys_pidfd_send_signal(%d->%d, SIGCONT)\n", self, strerror(errno), ret, pidfd, pid);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = sys_pidfd_send_signal(%d->%d, SIGCONT)\n", self, ret, pidfd, pid);

		ret = waitid(P_PID, pid, &info, WEXITED | __WALL);
		if (ret) {
			printf("FAIL(%d): %s - %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, strerror(errno), ret, pid);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, ret, pid);

		/*
		 * The child is now in EXIT_TRACE == (EXIT_ZOMBIE | EXIT_DEAD).
		 * Detach from it which will cause the parent to be notified.
		 */
		ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
		if (ret) {
			printf("FAIL(%d): %s - %zd = ptrace(PTRACE_DETACH, %d, NULL, NULL)\n", self, strerror(errno), ret, pid);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = ptrace(PTRACE_DETACH, %d, NULL, NULL)\n", self, ret, pid);

		printf("SUCC(%d): Calling raise(SIGSTOP) for %d\n", self, self);
		ret = raise(SIGSTOP);
		if (ret) {
			printf("FAIL(%d): %s - %zd = raise(SIGSTOP) for %d\n", self, strerror(errno), ret, self);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = raise(SIGSTOP) for %d\n", self, ret, self);

		/* Use a slight delay. */
		sleep(2);

		/* This is the last close and will reap the first child. */
		ret = close(pidfd);
		if (ret) {
			printf("FAIL(%d): %s - %zd = close(%d->%d);\n", self, strerror(errno), ret, pidfd, pid);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = close(%d->%d);\n", self, ret, pidfd, pid);

		exit(EXIT_SUCCESS);
	}

	/* Wait for the second process to have stopped. */
	ret = waitid(P_PID, pid_sibling, &info, WSTOPPED | __WALL);
	if (ret) {
		printf("FAIL(%d): %s - %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, strerror(errno), ret, pid_sibling);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, ret, pid_sibling);

	/*
	 * Process requires CLONE_WAIT_PIDFD and we're no tracing it so this
	 * must fail.
	 */
	ret = waitid(P_PID, pid, &info, WEXITED | __WALL);
	if (ret == 0) {
		printf("FAIL(%d): %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, ret, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %s - %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, strerror(errno), ret, pid);

	/*
	 * After this close there's still a pidfd referencing pid so this won't
	 * reap the task.
	 */
	ret = close(pidfd);
	if (ret) {
		printf("FAIL(%d): %s - %zd = close(%d->%d);\n", self, strerror(errno), ret, pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = close(%d->%d);\n", self, ret, pidfd, pid);

	sleep(2);
	/* Continue second proces. */
	ret = kill(pid_sibling, SIGCONT);
	if (ret) {
		printf("FAIL(%d): %s - %zd = kill(%d, SIGCONT);\n", self, strerror(errno), ret, pid_sibling);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = kill(%d, SIGCONT);\n", self, ret, pid_sibling);

	/* Reap second process. */
	ret = waitid(P_PID, pid_sibling, &info, WEXITED | __WALL);
	if (ret) {
		printf("FAIL(%d): %s - %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, strerror(errno), ret, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, ret, pid);
}

static void test_ptrace_reparented(void)
{
	int pidfd = -1;
	struct clone_args args = {
		.pidfd = ptr_to_u64(&pidfd),

		/*
		 * Create process as CLONE_VFORK to suspend parent execution
		 * until the child has exited. This ensure that the parent sees
		 * the child in EXIT_ZOMBIE state.
		 */
		.flags = CLONE_PIDFD,
		.exit_signal = SIGCHLD,
	};
	ssize_t ret;
	pid_t pid, self;
	pid_t pid_sibling;
	siginfo_t info = {
		.si_signo = 0,
	};

	self = getpid();
	printf("Calling function %s in process %d\n", __FUNCTION__, self);

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("FAIL(%d): Failed to create new process\n", self);
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		self = getpid();
		printf("SUCC(%d): Child process with pid %d\n", self, self);

		ret = raise(SIGSTOP);
		if (ret) {
			printf("FAIL(%d): Raise SIGSTOP signal for pid %d\n", self, self);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): Raised SIGSTOP signal for %d\n", self, self);
		exit(EXIT_SUCCESS);
	}

	ret = waitid(P_PID, pid, &info, WSTOPPED | __WALL);
	if (ret) {
		printf("FAIL(%d): %s - %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, strerror(errno), ret, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, ret, pid);

	/* Process is now stopped. */

	pid_sibling = fork();
	if (pid_sibling < 0) {
		printf("FAIL(%d): Failed to create second process\n", self);
		exit(EXIT_FAILURE);
	}

	if (pid_sibling == 0) {
		self = getpid();

		/*
		 * Trace a the non-child process pid. This means pid has now
		 * been reparented to us.
		 */
		ret = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
		if (ret) {
			printf("FAIL(%d): %s - %zd = ptrace(PTRACE_SEIZE, %d, NULL, NULL)\n", self, strerror(errno), ret, pid);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = ptrace(PTRACE_SEIZE, %d, NULL, NULL)\n", self, ret, pid);

		ret = sys_pidfd_send_signal(pidfd, SIGCONT);
		if (ret) {
			printf("FAIL(%d): %s - %zd = sys_pidfd_send_signal(%d->%d, SIGCONT)\n", self, strerror(errno), ret, pidfd, pid);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = sys_pidfd_send_signal(%d->%d, SIGCONT)\n", self, ret, pidfd, pid);

		ret = waitid(P_PID, pid, &info, WEXITED | __WALL);
		if (ret) {
			printf("FAIL(%d): %s - %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, strerror(errno), ret, pid);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, ret, pid);

		/*
		 * Detach from it which will cause the parent to be notified.
		 */
		ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
		if (ret) {
			printf("FAIL(%d): %s - %zd = ptrace(PTRACE_DETACH, %d, NULL, NULL)\n", self, strerror(errno), ret, pid);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = ptrace(PTRACE_DETACH, %d, NULL, NULL)\n", self, ret, pid);

		printf("SUCC(%d): Calling raise(SIGSTOP) for %d\n", self, self);
		ret = raise(SIGSTOP);
		if (ret) {
			printf("FAIL(%d): %s - %zd = raise(SIGSTOP) for %d\n", self, strerror(errno), ret, self);
			_exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = raise(SIGSTOP) for %d\n", self, ret, self);

		/* Use a slight delay. */
		sleep(2);

		/* This is the last close and will reap the first child. */
		ret = close(pidfd);
		if (ret) {
			printf("FAIL(%d): %s - %zd = close(%d->%d);\n", self, strerror(errno), ret, pidfd, pid);
			exit(EXIT_FAILURE);
		}
		printf("SUCC(%d): %zd = close(%d->%d);\n", self, ret, pidfd, pid);

		exit(EXIT_SUCCESS);
	}

	/* Wait for the second process to have stopped. */
	ret = waitid(P_PID, pid_sibling, &info, WSTOPPED | __WALL);
	if (ret) {
		printf("FAIL(%d): %s - %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, strerror(errno), ret, pid_sibling);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = waitid(P_PID, %d, &info, WSTOPPED | __WALL)\n", self, ret, pid_sibling);

	/*
	 * After this close there's still a pidfd referencing pid so this won't
	 * reap the task.
	 */
	ret = close(pidfd);
	if (ret) {
		printf("FAIL(%d): %s - %zd = close(%d->%d);\n", self, strerror(errno), ret, pidfd, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = close(%d->%d);\n", self, ret, pidfd, pid);

	sleep(2);
	/* Continue second proces. */
	ret = kill(pid_sibling, SIGCONT);
	if (ret) {
		printf("FAIL(%d): %s - %zd = kill(%d, SIGCONT);\n", self, strerror(errno), ret, pid_sibling);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = kill(%d, SIGCONT);\n", self, ret, pid_sibling);

	/* Reap second process. */
	ret = waitid(P_PID, pid_sibling, &info, WEXITED | __WALL);
	if (ret) {
		printf("FAIL(%d): %s - %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, strerror(errno), ret, pid);
		exit(EXIT_FAILURE);
	}
	printf("SUCC(%d): %zd = waitid(P_PID, %d, &info, WEXITED | __WALL);\n", self, ret, pid);
}

static void test_in_new_pid_namespace(void)
{
	int status = 0;
	struct clone_args args = {
		/*
		 * Create new pid namespace that we own so pids cannot easily
		 * get recycled behind our back. This is needed to test whether
		 * or not a CLONE_WAIT_PIDFD process leaves unintended zombies
		 * behind.
		 */
		.flags = CLONE_NEWPID | CLONE_NEWNS,
		.exit_signal = SIGCHLD,
	};
	pid_t pid, pid_ret;

	printf("Calling function %s in process %d\n", __FUNCTION__, getpid());

	pid = sys_clone3(&args);
	if (pid < 0) {
		printf("FAIL: Failed to create process in new pid namespace\n");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		int ret;

		printf("Child in new pid and mount namespace with pid %d\n", getpid());

		ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0);
		if (ret) {
			printf("FAIL: %s - Failed to remount / private\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = mount(NULL, "/proc", "proc", 0, NULL);
		if (ret < 0) {
			printf("FAIL: %s - Failed to remount /proc", strerror(errno));
			exit(EXIT_FAILURE);
		}

		test_no_wait_without_pidfd();
		test_parent_close_last_pidfd_before_exit();
		test_parent_close_last_pidfd_before_exit_ptrace();
		test_parent_close_last_pidfd_after_exit();
		test_stranger_close_last_pidfd_after_exit();
		test_ptrace_reparented();
		test_ptrace_reparented_pidfd();
		exit(EXIT_SUCCESS);
	}

	pid_ret = waitpid(pid, &status, __WALL);
	if (pid_ret < 0) {
		printf("FAIL: Failed to wait on process\n");
		exit(EXIT_FAILURE);
	}

	if (!WIFEXITED(status)) {
		printf("FAIL: Process did not exit cleanly\n");
		exit(EXIT_FAILURE);
	}

	if (WEXITSTATUS(status)) {
		printf("FAIL: Test suite failed\n");
		exit(EXIT_FAILURE);
	}
}

static inline void test_in_current_pid_namespace(void)
{
	test_no_wait_without_pidfd();
	test_parent_close_last_pidfd_before_exit();
	test_parent_close_last_pidfd_before_exit_ptrace();
	test_parent_close_last_pidfd_after_exit();
	test_stranger_close_last_pidfd_after_exit();
	test_ptrace_reparented();
	test_ptrace_reparented_pidfd();
}

int main(int argc, char *argv[])
{
	test_in_current_pid_namespace();
	test_in_new_pid_namespace();
	exit(EXIT_SUCCESS);
}
