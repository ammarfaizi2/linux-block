// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2021 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2020-2021 The Linux Foundation
 *
 * Test the readfile() syscall in various ways.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>

#include "../kselftest.h"
#include "readfile.h"

#define TEST_FILE1	"/sys/devices/system/cpu/vulnerabilities/meltdown"
#define TEST_FILE2	"/sys/devices/system/cpu/vulnerabilities/spectre_v1"
#define TEST_FILE4	"/sys/kernel/debug/usb/devices"

/*
 * Test that readfile() is even in the running kernel or not.
 */
static void test_readfile_supported(void)
{
	const char *proc_map = "/proc/self/maps";
	unsigned char buffer[10];
	int retval;

	if (__NR_readfile < 0)
		ksft_exit_skip("readfile() syscall is not defined for the kernel this test was built against\n");

	/*
	 * Do a simple test to see if the syscall really is present in the
	 * running kernel
	 */
	retval = sys_readfile(0, proc_map, &buffer[0], sizeof(buffer), 0);
	if (retval == -1)
		ksft_exit_skip("readfile() syscall not present on running kernel\n");

	ksft_test_result_pass("readfile() syscall present\n");
}

/*
 * Open all files in a specific sysfs directory and read from them
 *
 * This tests the "openat" type functionality of opening all files relative to a
 * directory.  We don't care at the moment about the contents.
 */
static void test_sysfs_files(void)
{
	static unsigned char buffer[8000];
	const char *sysfs_dir = "/sys/devices/system/cpu/vulnerabilities/";
	struct dirent *dirent;
	DIR *vuln_sysfs_dir;
	int sysfs_fd;
	int retval;

	sysfs_fd = open(sysfs_dir, O_PATH | O_DIRECTORY);
	if (sysfs_fd == -1) {
		ksft_test_result_skip("unable to open %s directory\n",
				      sysfs_dir);
		return;
	}

	vuln_sysfs_dir = opendir(sysfs_dir);
	if (!vuln_sysfs_dir) {
		ksft_test_result_skip("%s unable to be opened, skipping test\n");
		return;
	}

	ksft_print_msg("readfile: testing relative path functionality by reading files in %s\n",
		       sysfs_dir);
	/* open all sysfs file in this directory and read the whole thing */
	while ((dirent = readdir(vuln_sysfs_dir))) {
		/* ignore . and .. */
		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0)
			continue;

		retval = sys_readfile(sysfs_fd, dirent->d_name, &buffer[0],
				      sizeof(buffer), 0);

		if (retval <= 0) {
			ksft_test_result_fail("readfile(%s) failed with %d\n",
					      dirent->d_name, retval);
			goto exit;
		}

		/* cut off trailing \n character */
		buffer[retval - 1] = 0x00;
		ksft_print_msg("    '%s' contains \"%s\"\n", dirent->d_name,
			       buffer);
	}

	ksft_test_result_pass("readfile() relative path functionality passed\n");

exit:
	closedir(vuln_sysfs_dir);
	close(sysfs_fd);
}

/* Temporary directory variables */
static int root_fd;		/* test root directory file handle */
static char tmpdir[PATH_MAX];

static void setup_tmpdir(void)
{
	char *tmpdir_root;

	tmpdir_root = getenv("TMPDIR");
	if (!tmpdir_root)
		tmpdir_root = "/tmp";

	snprintf(tmpdir, PATH_MAX, "%s/readfile.XXXXXX", tmpdir_root);
	if (!mkdtemp(tmpdir)) {
		ksft_test_result_fail("mkdtemp(%s) failed\n", tmpdir);
		ksft_exit_fail();
	}

	root_fd = open(tmpdir, O_PATH | O_DIRECTORY);
	if (root_fd == -1) {
		ksft_exit_fail_msg("%s unable to be opened, error = %d\n",
				   tmpdir, root_fd);
		ksft_exit_fail();
	}

	ksft_print_msg("%s created to use for testing\n", tmpdir);
}

static void teardown_tmpdir(void)
{
	int retval;

	close(root_fd);

	retval = rmdir(tmpdir);
	if (retval) {
		ksft_exit_fail_msg("%s removed with return value %d\n",
				   tmpdir, retval);
		ksft_exit_fail();
	}
	ksft_print_msg("%s cleaned up and removed\n", tmpdir);

}

static void test_filesize(size_t size)
{
	char filename[PATH_MAX];
	unsigned char *write_data;
	unsigned char *read_data;
	int fd;
	int retval;
	size_t i;

	snprintf(filename, PATH_MAX, "size-%ld", size);

	read_data = malloc(size);
	write_data = malloc(size);
	if (!read_data || !write_data)
		ksft_exit_fail_msg("Unable to allocate %ld bytes\n", size);

	fd = openat(root_fd, filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0)
		ksft_exit_fail_msg("Unable to create file %s\n", filename);

	ksft_print_msg("%s created\n", filename);

	for (i = 0; i < size; ++i)
		write_data[i] = (unsigned char)(0xff & i);

	write(fd, write_data, size);
	close(fd);

	retval = sys_readfile(root_fd, filename, read_data, size, 0);

	if (retval != size) {
		ksft_test_result_fail("Read %d bytes but wanted to read %ld bytes.\n",
				      retval, size);
		goto exit;
	}

	if (memcmp(read_data, write_data, size) != 0) {
		ksft_test_result_fail("Read data of buffer size %d did not match written data\n",
				      size);
		goto exit;
	}

	ksft_test_result_pass("readfile() of size %ld succeeded.\n", size);

exit:
	unlinkat(root_fd, filename, 0);
	free(write_data);
	free(read_data);
}


/*
 * Create a bunch of differently sized files, and verify we read the correct
 * amount of data from them.
 */
static void test_filesizes(void)
{
	setup_tmpdir();

	test_filesize(0x10);
	test_filesize(0x100);
	test_filesize(0x1000);
	test_filesize(0x10000);
	test_filesize(0x100000);
	test_filesize(0x1000000);

	teardown_tmpdir();

}

static void readfile(const char *filename)
{
//	int root_fd;
	unsigned char buffer[16000];
	int retval;

	memset(buffer, 0x00, sizeof(buffer));

//	root_fd = open("/", O_DIRECTORY);
//	if (root_fd == -1)
//		ksft_exit_fail_msg("error with root_fd\n");

	retval = sys_readfile(root_fd, filename, &buffer[0], sizeof(buffer), 0);

//	close(root_fd);

	if (retval <= 0)
		ksft_test_result_fail("readfile() test of filename=%s failed with retval %d\n",
				      filename, retval);
	else
		ksft_test_result_pass("readfile() test of filename=%s succeeded with retval=%d\n",
				      filename, retval);
//	buffer='%s'\n",
//	       filename, retval, &buffer[0]);

}


int main(int argc, char *argv[])
{
	ksft_print_header();
	ksft_set_plan(10);

	test_readfile_supported();	// 1 test

	test_sysfs_files();		// 1 test

	test_filesizes();		// 6 tests

	setup_tmpdir();

	readfile(TEST_FILE1);
	readfile(TEST_FILE2);
//	readfile(TEST_FILE4);

	teardown_tmpdir();

	if (ksft_get_fail_cnt())
		return ksft_exit_fail();

	return ksft_exit_pass();
}

