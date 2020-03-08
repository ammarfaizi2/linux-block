// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2021 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2020-2021 The Linux Foundation
 *
 * Tiny test program to try to benchmark the speed of the readfile syscall vs.
 * the open/read/close sequence it can replace.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "readfile.h"

/* Default test file if no one wants to pick something else */
#define DEFAULT_TEST_FILE	"/sys/devices/system/cpu/vulnerabilities/meltdown"

#define DEFAULT_TEST_LOOPS	1000

#define DEFAULT_TEST_TYPE	"both"

/* Max number of bytes that will be read from the file */
#define TEST_BUFFER_SIZE	10000
static unsigned char test_buffer[TEST_BUFFER_SIZE];

enum test_type {
	TEST_READFILE,
	TEST_OPENREADCLOSE,
	TEST_BOTH,
};

/* Test that readfile() is even in the running kernel or not.  */
static void test_readfile_supported(void)
{
	const char *proc_map = "/proc/self/maps";
	unsigned char buffer[10];
	int retval;

	if (__NR_readfile < 0) {
		fprintf(stderr,
			"readfile() syscall is not defined for the kernel this test was built against.\n");
		exit(1);
	}

	/*
	 * Do a simple test to see if the syscall really is present in the
	 * running kernel
	 */
	retval = sys_readfile(0, proc_map, &buffer[0], sizeof(buffer), 0);
	if (retval == -1) {
		fprintf(stderr,
			"readfile() syscall not present on running kernel.\n");
		exit(1);
	}
}

static inline long long get_time_ns(void)
{
        struct timespec t;

        clock_gettime(CLOCK_MONOTONIC, &t);

        return (long long)t.tv_sec * 1000000000 + t.tv_nsec;
}

/* taken from all-io.h from util-linux repo */
static inline ssize_t read_all(int fd, unsigned char *buf, size_t count)
{
	ssize_t ret;
	ssize_t c = 0;
	int tries = 0;

	while (count > 0) {
		ret = read(fd, buf, count);
		if (ret <= 0) {
			if (ret < 0 && (errno == EAGAIN || errno == EINTR) &&
			    (tries++ < 5)) {
				usleep(250000);
				continue;
			}
			return c ? c : -1;
		}
		tries = 0;
		count -= ret;
		buf += ret;
		c += ret;
	}
	return c;
}

static int openreadclose(const char *filename, unsigned char *buffer,
			 size_t bufsize)
{
	size_t count;
	int fd;

	fd = openat(0, filename, O_RDONLY);
	if (fd < 0) {
		printf("error opening %s\n", filename);
		return fd;
	}

	count = read_all(fd, buffer, bufsize);
	if (count < 0) {
		printf("Error %ld reading from %s\n", count, filename);
	}

	close(fd);
	return count;
}

static int run_test(enum test_type test_type, const char *filename)
{
	switch (test_type) {
	case TEST_READFILE:
		return sys_readfile(0, filename, &test_buffer[0],
				    TEST_BUFFER_SIZE, O_RDONLY);

	case TEST_OPENREADCLOSE:
		return openreadclose(filename, &test_buffer[0],
				     TEST_BUFFER_SIZE);
	default:
		return -EINVAL;
	}
}

static const char * const test_names[] = {
	[TEST_READFILE]		= "readfile",
	[TEST_OPENREADCLOSE]	= "open/read/close",
};

static int run_test_loop(int loops, enum test_type test_type,
			 const char *filename)
{
	long long time_start;
	long long time_end;
	long long time_elapsed;
	int retval = 0;
	int i;

	fprintf(stdout,
		"Running %s test on file %s for %d loops...\n",
		test_names[test_type], filename, loops);

	/* Fill the cache with one run of the read first */
	retval = run_test(test_type, filename);
	if (retval < 0) {
		fprintf(stderr,
			"test %s was unable to run with error %d\n",
			test_names[test_type], retval);
		return retval;
	}

	time_start = get_time_ns();

	for (i = 0; i < loops; ++i) {
		retval = run_test(test_type, filename);

		if (retval < 0) {
			fprintf(stderr,
				"test failed on loop %d with error %d\n",
				i, retval);
			break;
		}
	}
	time_end = get_time_ns();

	time_elapsed = time_end - time_start;

	fprintf(stdout, "Took %lld ns\n", time_elapsed);

	return retval;
}

static int do_read_file_test(int loops, enum test_type test_type,
			     const char *filename)
{
	int retval;

	if (test_type == TEST_BOTH) {
		retval = do_read_file_test(loops, TEST_READFILE, filename);
		retval = do_read_file_test(loops, TEST_OPENREADCLOSE, filename);
		return retval;
	}
	return run_test_loop(loops, test_type, filename);
}

static int check_file_present(const char *filename)
{
	struct stat sb;
	int retval;

	retval = stat(filename, &sb);
	if (retval == -1) {
		fprintf(stderr,
			"filename %s is not present\n", filename);
		return retval;
	}

	if ((sb.st_mode & S_IFMT) != S_IFREG) {
		fprintf(stderr,
			"filename %s must be a real file, not anything else.\n",
			filename);
		return -1;
	}
	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		" -l loops     Number of loops to run the test for.\n"
		"              default is %d\n"
		" -t testtype  Test type to run.\n"
		"              types are: readfile, openreadclose, both\n"
		"              default is %s\n"
		" -f filename  Filename to read from, full path, not relative.\n"
		"              default is %s\n",
		progname,
		DEFAULT_TEST_LOOPS, DEFAULT_TEST_TYPE, DEFAULT_TEST_FILE);
}

int main(int argc, char *argv[])
{
	char *progname;
	char *testtype = DEFAULT_TEST_TYPE;
	char *filename = DEFAULT_TEST_FILE;
	int loops = DEFAULT_TEST_LOOPS;
	enum test_type test_type;
	int retval;
	char c;

	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];

	while (EOF != (c = getopt(argc, argv, "t:l:f:h"))) {
		switch (c) {
		case 'l':
			loops = atoi(optarg);
			break;

		case 't':
			testtype = optarg;
			break;

		case 'f':
			filename = optarg;
			break;

		case 'h':
			usage(progname);
			return 0;

		default:
			usage(progname);
			return -1;
		}
	}

	if (strcmp(testtype, "readfile") == 0)
		test_type = TEST_READFILE;
	else if (strcmp(testtype, "openreadclose") == 0)
		test_type = TEST_OPENREADCLOSE;
	else if (strcmp(testtype, "both") == 0)
		test_type = TEST_BOTH;
	else {
		usage(progname);
		return -1;
	}

	test_readfile_supported();

	retval = check_file_present(filename);
	if (retval)
		return retval;

	return do_read_file_test(loops, test_type, filename);
}
