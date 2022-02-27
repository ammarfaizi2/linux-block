#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>


char **environ;

#define CASE_ERR(err) \
	case err: return #err

/* declare tests based on line numbers. There must be exactly one test per line. */
#define CASE_TEST(name) \
	case __LINE__: llen += printf("%d %s", test, #name);

const char *strerror(int err)
{
	switch (err) {
	case 0: return "SUCCESS";
	CASE_ERR(EPERM);
	CASE_ERR(ENOENT);
	CASE_ERR(ESRCH);
	CASE_ERR(EINTR);
	CASE_ERR(EIO);
	CASE_ERR(ENXIO);
	CASE_ERR(E2BIG);
	CASE_ERR(ENOEXEC);
	CASE_ERR(EBADF);
	CASE_ERR(ECHILD);
	CASE_ERR(EAGAIN);
	CASE_ERR(ENOMEM);
	CASE_ERR(EACCES);
	CASE_ERR(EFAULT);
	CASE_ERR(ENOTBLK);
	CASE_ERR(EBUSY);
	CASE_ERR(EEXIST);
	CASE_ERR(EXDEV);
	CASE_ERR(ENODEV);
	CASE_ERR(ENOTDIR);
	CASE_ERR(EISDIR);
	CASE_ERR(EINVAL);
	CASE_ERR(ENFILE);
	CASE_ERR(EMFILE);
	CASE_ERR(ENOTTY);
	CASE_ERR(ETXTBSY);
	CASE_ERR(EFBIG);
	CASE_ERR(ENOSPC);
	CASE_ERR(ESPIPE);
	CASE_ERR(EROFS);
	CASE_ERR(EMLINK);
	CASE_ERR(EPIPE);
	CASE_ERR(EDOM);
	CASE_ERR(ERANGE);
	CASE_ERR(ENOSYS);
	default:
		return itoa(err);
	}
}

static int pad_spc(int llen, int cnt, const char *fmt, ...)
{
	va_list args;
	int len;
	int ret;

	for (len = 0; len < cnt - llen; len++)
		putchar(' ');

	va_start(args, fmt);
	ret = vfprintf(stdout, fmt, args);
	va_end(args);
	return ret < 0 ? ret : ret + len;
}


#define EXPECT_ZR(expr)					\
	do { ret |= expect_zr(expr, llen); } while (0)

static int expect_zr(int expr, int llen)
{
	int ret = !(expr == 0);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_NZ(expr, val)				\
	do { ret |= expect_nz(expr, llen; } while (0)

static int expect_nz(int expr, int llen)
{
	int ret = !(expr != 0);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_EQ(expr, val)					\
	do { ret |= expect_eq(expr, llen, val); } while (0)

static int expect_eq(int expr, int llen, int val)
{
	int ret = !(expr == val);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_NE(expr, val)					\
	do { ret |= expect_ne(expr, llen, val); } while (0)

static int expect_ne(int expr, int llen, int val)
{
	int ret = !(expr != val);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_GE(expr, val)					\
	do { ret |= expect_ge(expr, llen, val); } while (0)

static int expect_ge(int expr, int llen, int val)
{
	int ret = !(expr >= val);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_GT(expr, val)					\
	do { ret |= expect_gt(expr, llen, val); } while (0)

static int expect_gt(int expr, int llen, int val)
{
	int ret = !(expr > val);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_LE(expr, val)					\
	do { ret |= expect_le(expr, llen, val); } while (0)

static int expect_le(int expr, int llen, int val)
{
	int ret = !(expr <= val);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_LT(expr, val)					\
	do { ret |= expect_lt(expr, llen, val); } while (0)

static int expect_lt(int expr, int llen, int val)
{
	int ret = !(expr < val);

	llen += printf(" = %d ", expr);
	pad_spc(llen, 40, ret ? "[FAIL]\n" : " [OK]\n");
	return ret;
}


#define EXPECT_SYSZR(expr)					\
	do { ret |= expect_syszr(expr, llen); } while (0)

static int expect_syszr(int expr, int llen)
{
	int ret = 0;

	if (expr) {
		ret = 1;
		llen += printf(" = %d %s ", expr, strerror(errno));
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += printf(" = %d ", expr);
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_SYSEQ(expr, val)					\
	do { ret |= expect_syseq(expr, llen, val); } while (0)

static int expect_syseq(int expr, int llen, int val)
{
	int ret = 0;

	if (expr != val) {
		ret = 1;
		llen += printf(" = %d %s ", expr, strerror(errno));
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += printf(" = %d ", expr);
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_SYSNE(expr, val)					\
	do { ret |= expect_sysne(expr, llen, val); } while (0)

static int expect_sysne(int expr, int llen, int val)
{
	int ret = 0;

	if (expr == val) {
		ret = 1;
		llen += printf(" = %d %s ", expr, strerror(errno));
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += printf(" = %d ", expr);
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_SYSER(expr, expret, experr)				\
	do { ret |= expect_syserr(expr, expret, experr, llen); } while (0)

static int expect_syserr(int expr, int expret, int experr, int llen)
{
	int ret = 0;
	int _errno = errno;

	llen += printf(" = %d %s ", expr, strerror(_errno));
	if (expr != expret || _errno != experr) {
		ret = 1;
		llen += printf(" != (%d %s) ", expret, strerror(experr));
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_PTRZR(expr)					\
	do { ret |= expect_ptrzr(expr, llen); } while (0)

static int expect_ptrzr(const void *expr, int llen)
{
	int ret = 0;

	llen += printf(" = <%p> ", expr);
	if (expr) {
		ret = 1;
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_PTRNZ(expr)					\
	do { ret |= expect_ptrnz(expr, llen); } while (0)

static int expect_ptrnz(const void *expr, int llen)
{
	int ret = 0;

	llen += printf(" = <%p> ", expr);
	if (!expr) {
		ret = 1;
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_STRZR(expr)					\
	do { ret |= expect_strzr(expr, llen); } while (0)

static int expect_strzr(const char *expr, int llen)
{
	int ret = 0;

	llen += printf(" = <%s> ", expr);
	if (expr) {
		ret = 1;
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_STRNZ(expr)					\
	do { ret |= expect_strnz(expr, llen); } while (0)

static int expect_strnz(const char *expr, int llen)
{
	int ret = 0;

	llen += printf(" = <%s> ", expr);
	if (!expr) {
		ret = 1;
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_STREQ(expr, cmp)					\
	do { ret |= expect_streq(expr, llen, cmp); } while (0)

static int expect_streq(const char *expr, int llen, const char *cmp)
{
	int ret = 0;

	llen += printf(" = <%s> ", expr);
	if (strcmp(expr, cmp) != 0) {
		ret = 1;
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


#define EXPECT_STRNE(expr, cmp)					\
	do { ret |= expect_strne(expr, llen, cmp); } while (0)

static int expect_strne(const char *expr, int llen, const char *cmp)
{
	int ret = 0;

	llen += printf(" = <%s> ", expr);
	if (strcmp(expr, cmp) == 0) {
		ret = 1;
		llen += pad_spc(llen, 40, "[FAIL]\n");
	} else {
		llen += pad_spc(llen, 40, " [OK]\n");
	}
	return ret;
}


int test_getdents64(const char *dir)
{
	char buffer[4096];
	int fd, ret;
	int err;

        ret = fd = open(dir, O_RDONLY | O_DIRECTORY, 0);
        if (ret < 0)
		return ret;

        ret = getdents64(fd, (void *)buffer, sizeof(buffer));
	err = errno;
	close(fd);

	errno = err;
	return ret;
}

int run_syscalls(int min, int max)
{
	int test;
	int tmp;
	int ret = 0;
	void *p1, *p2;

	for (test = min; test >= 0 && test <= max; test++) {
		int llen = 0; // line length

		/* avoid leaving empty lines below, this will insert holes into
		 * test numbers.
		 */
		switch (test + __LINE__ + 1) {
		CASE_TEST(getpid);            EXPECT_SYSNE(getpid(), -1); break;
		CASE_TEST(getppid);           EXPECT_SYSNE(getppid(), -1); break;
		CASE_TEST(gettid);            EXPECT_SYSNE(gettid(), -1); break;
		CASE_TEST(getpgid_self);      EXPECT_SYSNE(getpgid(0), -1); break;
		CASE_TEST(getpgid_bad);       EXPECT_SYSER(getpgid(-1), -1, ESRCH); break;
		CASE_TEST(kill_0);            EXPECT_SYSZR(kill(getpid(), 0)); break;
		CASE_TEST(kill_CONT);         EXPECT_SYSZR(kill(getpid(), 0)); break;
		CASE_TEST(kill_BADPID);       EXPECT_SYSER(kill(INT_MAX, 0), -1, ESRCH); break;
		CASE_TEST(sbrk);              if ((p1=p2=sbrk(4096)) != (void *)-1) p2 = sbrk(-4096); EXPECT_SYSZR((p2 == (void*)-1) || p2 == p1); break;
		CASE_TEST(brk);               EXPECT_SYSZR(brk(sbrk(0))); break;
		CASE_TEST(chdir_root);        EXPECT_SYSZR(chdir("/")); break;
		CASE_TEST(chdir_dot);         EXPECT_SYSZR(chdir(".")); break;
		CASE_TEST(chdir_blah);        EXPECT_SYSER(chdir("/blah"), -1, ENOENT); break;
		CASE_TEST(chmod_net);         EXPECT_SYSZR(chmod("/proc/self/net", 0555)); break;
		CASE_TEST(chmod_self);        EXPECT_SYSER(chmod("/proc/self", 0555), -1, EPERM); break;
		CASE_TEST(chown_self);        EXPECT_SYSER(chown("/proc/self", 0, 0), -1, EPERM); break;
		CASE_TEST(chroot_root);       EXPECT_SYSZR(chroot("/")); break;
		CASE_TEST(chroot_blah);       EXPECT_SYSER(chroot("/proc/self/blah"), -1, ENOENT); break;
		CASE_TEST(chroot_exe);        EXPECT_SYSER(chroot("/proc/self/exe"), -1, ENOTDIR); break;
		CASE_TEST(close_m1);          EXPECT_SYSER(close(-1), -1, EBADF); break;
		CASE_TEST(close_dup);         EXPECT_SYSZR(close(dup(0))); break;
		CASE_TEST(dup_0);             tmp = dup(0);  EXPECT_SYSNE(tmp, -1); close(tmp); break;
		CASE_TEST(dup_m1);            tmp = dup(-1); EXPECT_SYSER(tmp, -1, EBADF); if (tmp != -1) close(tmp); break;
		CASE_TEST(dup2_0);            tmp = dup2(0, 100);  EXPECT_SYSNE(tmp, -1); close(tmp); break;
		CASE_TEST(dup2_m1);           tmp = dup2(-1, 100); EXPECT_SYSER(tmp, -1, EBADF); if (tmp != -1) close(tmp); break;
		CASE_TEST(dup3_0);            tmp = dup3(0, 100, 0);  EXPECT_SYSNE(tmp, -1); close(tmp); break;
		CASE_TEST(dup3_m1);           tmp = dup3(-1, 100, 0); EXPECT_SYSER(tmp, -1, EBADF); if (tmp != -1) close(tmp); break;
		CASE_TEST(execve_root);       EXPECT_SYSER(execve("/", NULL, NULL), -1, EACCES); break;
		CASE_TEST(getdents64_root);   EXPECT_SYSNE(test_getdents64("/"), -1); break;
		CASE_TEST(getdents64_null);   EXPECT_SYSER(test_getdents64("/dev/null"), -1, ENOTDIR); break;
		CASE_TEST(gettimeofday_null); EXPECT_SYSZR(gettimeofday(NULL, NULL)); break;
		CASE_TEST(gettimeofday_bad1); EXPECT_SYSER(gettimeofday((void*)1, NULL), -1, EFAULT); break;
		CASE_TEST(gettimeofday_bad2); EXPECT_SYSER(gettimeofday(NULL, (void*)1), -1, EFAULT); break;
		CASE_TEST(gettimeofday_bad2); EXPECT_SYSER(gettimeofday(NULL, (void*)1), -1, EFAULT); break;
		CASE_TEST(ioctl_tiocinq);     EXPECT_SYSZR(ioctl(0, TIOCINQ, &tmp)); break;
		CASE_TEST(ioctl_tiocinq);     EXPECT_SYSZR(ioctl(0, TIOCINQ, &tmp)); break;
		CASE_TEST(link_root1);        EXPECT_SYSER(link("/", "/"), -1, EEXIST); break;
		CASE_TEST(link_blah);         EXPECT_SYSER(link("/proc/self/blah", "/blah"), -1, ENOENT); break;
		CASE_TEST(link_dir);          EXPECT_SYSER(link("/", "/blah"), -1, EPERM); break;
		CASE_TEST(link_cross);        EXPECT_SYSER(link("/proc/self/net", "/blah"), -1, EXDEV); break;
		CASE_TEST(lseek_m1);          EXPECT_SYSER(lseek(-1, 0, SEEK_SET), -1, EBADF); break;
		CASE_TEST(lseek_0);           EXPECT_SYSER(lseek(0, 0, SEEK_SET), -1, ESPIPE); break;
		CASE_TEST(mkdir_root);        EXPECT_SYSER(mkdir("/", 0755), -1, EEXIST); break;
		CASE_TEST(open_tty);          EXPECT_SYSNE(tmp = open("/dev/null", 0), -1); if (tmp != -1) close(tmp); break;
		CASE_TEST(open_blah);         EXPECT_SYSER(tmp = open("/proc/self/blah", 0), -1, ENOENT); if (tmp != -1) close(tmp); break;
		CASE_TEST(poll_null);         EXPECT_SYSZR(poll(NULL, 0, 0)); break;
		CASE_TEST(poll_stdout);       EXPECT_SYSNE(({ struct pollfd fds = { 1, POLLOUT, 0}; poll(&fds, 1, 0); }), -1); break;
		CASE_TEST(poll_fault);        EXPECT_SYSER(poll((void*)1, 1, 0), -1, EFAULT); break;
		CASE_TEST(read_badf);         EXPECT_SYSER(read(-1, &tmp, 1), -1, EBADF); break;
		CASE_TEST(sched_yield);       EXPECT_SYSZR(sched_yield()); break;
		CASE_TEST(select_null);       EXPECT_SYSZR(({ struct timeval tv = { 0 }; select(0, NULL, NULL, NULL, &tv); })); break;
		CASE_TEST(select_stdout);     EXPECT_SYSNE(({ fd_set fds = { 2 /* stdout=1 */ }; select(2, NULL, &fds, NULL, NULL); }), -1); break;
		CASE_TEST(select_fault);      EXPECT_SYSER(select(1, (void*)1, NULL, NULL, 0), -1, EFAULT); break;
		CASE_TEST(stat_blah);         EXPECT_SYSER(({ struct stat buf; stat("/proc/self/blah", &buf); }), -1, ENOENT); break;
		CASE_TEST(stat_fault);        EXPECT_SYSER(({ struct stat buf; stat(NULL, &buf); }), -1, EFAULT); break;
		CASE_TEST(symlink_root);      EXPECT_SYSER(symlink("/", "/"), -1, EEXIST); break;
		CASE_TEST(unlink_root);       EXPECT_SYSER(unlink("/"), -1, EISDIR); break;
		CASE_TEST(unlink_blah);       EXPECT_SYSER(unlink("/proc/self/blah"), -1, ENOENT); break;
		CASE_TEST(wait_child);        EXPECT_SYSER(wait(&tmp), -1, ECHILD); break;
		CASE_TEST(waitpid_min);       EXPECT_SYSER(waitpid(INT_MIN, &tmp, WNOHANG), -1, ESRCH); break;
		CASE_TEST(waitpid_child);     EXPECT_SYSER(waitpid(getpid(), &tmp, WNOHANG), -1, ECHILD); break;
		CASE_TEST(write_badf);        EXPECT_SYSER(write(-1, &tmp, 1), -1, EBADF); break;
		CASE_TEST(write_zero);        EXPECT_SYSZR(write(1, &tmp, 0)); break;
		case __LINE__:
			return ret; /* must be last */
		/* note: do not set any defaults so as to permit holes above */
		}
	}
	return ret;
}

int main(int argc, char **argv, char **envp)
{
	int min = 0;
	int max = __INT_MAX__;
	int ret;
	char *test;

	environ = envp;

	if (argc > 1)
		min = atoi(argv[1]);

	if (argc > 2)
		max = atoi(argv[2]);

	ret = run_syscalls(min, max);
	printf("Exiting with status %d\n", ret);
	return ret;
}
