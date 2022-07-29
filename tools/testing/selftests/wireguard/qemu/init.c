// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <sys/sendfile.h>
#include <sys/sysmacros.h>
#include <sys/random.h>
#include <linux/random.h>
#include <linux/version.h>

__attribute__((noreturn)) static void poweroff(void)
{
	fflush(stdout);
	fflush(stderr);
	reboot(RB_AUTOBOOT);
	sleep(30);
	fprintf(stderr, "\x1b[37m\x1b[41m\x1b[1mFailed to power off!!!\x1b[0m\n");
	exit(1);
}

static void panic(const char *what)
{
	fprintf(stderr, "\n\n\x1b[37m\x1b[41m\x1b[1mSOMETHING WENT HORRIBLY WRONG\x1b[0m\n\n    \x1b[31m\x1b[1m%s: %s\x1b[0m\n\n\x1b[37m\x1b[44m\x1b[1mPower off...\x1b[0m\n\n", what, strerror(errno));
	poweroff();
}

#define pretty_message(msg) puts("\x1b[32m\x1b[1m" msg "\x1b[0m")

static void print_banner(void)
{
	struct utsname utsname;
	int len;

	if (uname(&utsname) < 0)
		panic("uname");

	len = strlen("    WireGuard Test Suite on       ") + strlen(utsname.sysname) + strlen(utsname.release) + strlen(utsname.machine);
	printf("\x1b[45m\x1b[33m\x1b[1m%*.s\x1b[0m\n\x1b[45m\x1b[33m\x1b[1m    WireGuard Test Suite on %s %s %s    \x1b[0m\n\x1b[45m\x1b[33m\x1b[1m%*.s\x1b[0m\n\n", len, "", utsname.sysname, utsname.release, utsname.machine, len, "");
}

static void seed_rng(void)
{
	int bits = 256, fd;

	if (!getrandom(NULL, 0, GRND_NONBLOCK))
		return;
	pretty_message("[+] Fake seeding RNG...");
	fd = open("/dev/random", O_WRONLY);
	if (fd < 0)
		panic("open(random)");
	if (ioctl(fd, RNDADDTOENTCNT, &bits) < 0)
		panic("ioctl(RNDADDTOENTCNT)");
	close(fd);
}

static void set_time(void)
{
	if (time(NULL))
		return;
	pretty_message("[+] Setting fake time...");
	if (stime(&(time_t){1433512680}) < 0)
		panic("settimeofday()");
}

static void mount_filesystems(void)
{
	pretty_message("[+] Mounting filesystems...");
	mkdir("/dev", 0755);
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mkdir("/tmp", 0755);
	mkdir("/run", 0755);
	mkdir("/var", 0755);
	if (mount("none", "/dev", "devtmpfs", 0, NULL))
		panic("devtmpfs mount");
	if (mount("none", "/proc", "proc", 0, NULL))
		panic("procfs mount");
	if (mount("none", "/sys", "sysfs", 0, NULL))
		panic("sysfs mount");
	if (mount("none", "/tmp", "tmpfs", 0, NULL))
		panic("tmpfs mount");
	if (mount("none", "/run", "tmpfs", 0, NULL))
		panic("tmpfs mount");
	if (mount("none", "/sys/kernel/debug", "debugfs", 0, NULL))
		; /* Not a problem if it fails.*/
	if (symlink("/run", "/var/run"))
		panic("run symlink");
	if (symlink("/proc/self/fd", "/dev/fd"))
		panic("fd symlink");
}

static void enable_logging(void)
{
	int fd;
	pretty_message("[+] Enabling logging...");
	fd = open("/proc/sys/kernel/printk", O_WRONLY);
	if (fd >= 0) {
		if (write(fd, "9\n", 2) != 2)
			panic("write(printk)");
		close(fd);
	}
	fd = open("/proc/sys/debug/exception-trace", O_WRONLY);
	if (fd >= 0) {
		if (write(fd, "1\n", 2) != 2)
			panic("write(exception-trace)");
		close(fd);
	}
}

static void kmod_selftests(void)
{
	FILE *file;
	char line[2048], *start, *pass;
	bool success = true;
	pretty_message("[+] Module self-tests:");
	file = fopen("/proc/kmsg", "r");
	if (!file)
		panic("fopen(kmsg)");
	if (fcntl(fileno(file), F_SETFL, O_NONBLOCK) < 0)
		panic("fcntl(kmsg, nonblock)");
	while (fgets(line, sizeof(line), file)) {
		start = strstr(line, "wireguard: ");
		if (!start)
			continue;
		start += 11;
		*strchrnul(start, '\n') = '\0';
		if (strstr(start, "www.wireguard.com"))
			break;
		pass = strstr(start, ": pass");
		if (!pass || pass[6] != '\0') {
			success = false;
			printf(" \x1b[31m*  %s\x1b[0m\n", start);
		} else
			printf(" \x1b[32m*  %s\x1b[0m\n", start);
	}
	fclose(file);
	if (!success) {
		puts("\x1b[31m\x1b[1m[-] Tests failed! \u2639\x1b[0m");
		poweroff();
	}
}

static void launch_tests(void)
{
	char cmdline[4096], *success_dev;
	int status, fd;
	pid_t pid;

	pretty_message("[+] Launching tests...");
	pid = fork();
	if (pid == -1)
		panic("fork");
	else if (pid == 0) {
		execl("/init.sh", "init", NULL);
		panic("exec");
	}
	if (waitpid(pid, &status, 0) < 0)
		panic("waitpid");
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		pretty_message("[+] Tests successful! :-)");
		fd = open("/proc/cmdline", O_RDONLY);
		if (fd < 0)
			panic("open(/proc/cmdline)");
		if (read(fd, cmdline, sizeof(cmdline) - 1) <= 0)
			panic("read(/proc/cmdline)");
		cmdline[sizeof(cmdline) - 1] = '\0';
		for (success_dev = strtok(cmdline, " \n"); success_dev; success_dev = strtok(NULL, " \n")) {
			if (strncmp(success_dev, "wg.success=", 11))
				continue;
			memcpy(success_dev + 11 - 5, "/dev/", 5);
			success_dev += 11 - 5;
			break;
		}
		if (!success_dev || !strlen(success_dev))
			panic("Unable to find success device");

		fd = open(success_dev, O_WRONLY);
		if (fd < 0)
			panic("open(success_dev)");
		if (write(fd, "success\n", 8) != 8)
			panic("write(success_dev)");
		close(fd);
	} else {
		const char *why = "unknown cause";
		int what = -1;

		if (WIFEXITED(status)) {
			why = "exit code";
			what = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			why = "signal";
			what = WTERMSIG(status);
		}
		printf("\x1b[31m\x1b[1m[-] Tests failed with %s %d! \u2639\x1b[0m\n", why, what);
	}
}

static void ensure_console(void)
{
	for (unsigned int i = 0; i < 1000; ++i) {
		int fd = open("/dev/console", O_RDWR);
		if (fd < 0) {
			usleep(50000);
			continue;
		}
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
		if (write(1, "\0\0\0\0\n", 5) == 5)
			return;
	}
	panic("Unable to open console device");
}

static void clear_leaks(void)
{
	int fd;

	fd = open("/sys/kernel/debug/kmemleak", O_WRONLY);
	if (fd < 0)
		return;
	pretty_message("[+] Starting memory leak detection...");
	write(fd, "clear\n", 5);
	close(fd);
}

static void check_leaks(void)
{
	int fd;

	fd = open("/sys/kernel/debug/kmemleak", O_WRONLY);
	if (fd < 0)
		return;
	pretty_message("[+] Scanning for memory leaks...");
	sleep(2); /* Wait for any grace periods. */
	write(fd, "scan\n", 5);
	close(fd);

	fd = open("/sys/kernel/debug/kmemleak", O_RDONLY);
	if (fd < 0)
		return;
	if (sendfile(1, fd, NULL, 0x7ffff000) > 0)
		panic("Memory leaks encountered");
	close(fd);
}

#include <elf.h>
#include <link.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>

#if ULONG_MAX == 0xffffffff
typedef Elf32_Ehdr Ehdr;
typedef Elf32_Phdr Phdr;
typedef Elf32_Sym Sym;
typedef Elf32_Verdef Verdef;
typedef Elf32_Verdaux Verdaux;
#else
typedef Elf64_Ehdr Ehdr;
typedef Elf64_Phdr Phdr;
typedef Elf64_Sym Sym;
typedef Elf64_Verdef Verdef;
typedef Elf64_Verdaux Verdaux;
#endif

static int checkver(Verdef *def, int vsym, const char *vername, char *strings)
{
	vsym &= 0x7fff;
	for (;;) {
		if (!(def->vd_flags & VER_FLG_BASE)
		  && (def->vd_ndx & 0x7fff) == vsym)
			break;
		if (def->vd_next == 0)
			return 0;
		def = (Verdef *)((char *)def + def->vd_next);
	}
	Verdaux *aux = (Verdaux *)((char *)def + def->vd_aux);
	return !strcmp(vername, strings + aux->vda_name);
}

#define OK_TYPES (1<<STT_NOTYPE | 1<<STT_OBJECT | 1<<STT_FUNC | 1<<STT_COMMON)
#define OK_BINDS (1<<STB_GLOBAL | 1<<STB_WEAK | 1<<STB_GNU_UNIQUE)

static void *__vdsosym(const char *vername, const char *name)
{
	size_t i;
	Ehdr *eh = (void *)getauxval(AT_SYSINFO_EHDR);
	Phdr *ph = (void *)((char *)eh + eh->e_phoff);
	size_t *dynv=0, base=-1;
	for (i=0; i<eh->e_phnum; i++, ph=(void *)((char *)ph+eh->e_phentsize)) {
		if (ph->p_type == PT_LOAD)
			base = (size_t)eh + ph->p_offset - ph->p_vaddr;
		else if (ph->p_type == PT_DYNAMIC)
			dynv = (void *)((char *)eh + ph->p_offset);
	}
	if (!dynv || base==(size_t)-1) return 0;

	char *strings = 0;
	Sym *syms = 0;
	Elf_Symndx *hashtab = 0;
	uint16_t *versym = 0;
	Verdef *verdef = 0;

	for (i=0; dynv[i]; i+=2) {
		void *p = (void *)(base + dynv[i+1]);
		switch(dynv[i]) {
		case DT_STRTAB: strings = p; break;
		case DT_SYMTAB: syms = p; break;
		case DT_HASH: hashtab = p; break;
		case DT_VERSYM: versym = p; break;
		case DT_VERDEF: verdef = p; break;
		}
	}	

	if (!strings || !syms || !hashtab) return 0;
	if (!verdef) versym = 0;

	for (i=0; i<hashtab[1]; i++) {
		if (!(1<<(syms[i].st_info&0xf) & OK_TYPES)) continue;
		if (!(1<<(syms[i].st_info>>4) & OK_BINDS)) continue;
		if (!syms[i].st_shndx) continue;
		if (strcmp(name, strings+syms[i].st_name)) continue;
		if (versym && !checkver(verdef, versym[i], vername, strings))
			continue;
		return (void *)(base + syms[i].st_value);
	}

	return 0;
}

#ifndef timespecsub
#define	timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (0)
#endif

static void *vgetrandom_alloc(size_t *num, size_t *size_per_each, unsigned int flags)
{
	enum { __NR_vgetrandom_alloc = 451 };
	unsigned long ret = syscall(__NR_vgetrandom_alloc, num, size_per_each, flags);
	if (ret > -4096UL) {
		errno = -ret;
		return NULL;
	}
	return (void *)ret;
}

static void vdso_stuff(void)
{
	void *grnd_state;
	ssize_t(*vgetrandom)(void *buf, size_t len, unsigned long flags, void *state) = __vdsosym("LINUX_2.6", "__vdso_getrandom");
	unsigned int val;
	unsigned long times;
	struct timespec start, end, diff;
	enum { TRIALS = 25000000 };
	size_t num = 1, size_per_each;

	grnd_state = vgetrandom_alloc(&num, &size_per_each, 0);
	if (!grnd_state)
		panic("vgetrandom_alloc failed");
	printf("Allocated %zu states of %zu bytes each\n", num, size_per_each);

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (times = 0; times < TRIALS; ++times) {
		ssize_t ret = vgetrandom(&val, sizeof(val), 0, grnd_state);
		if (ret != sizeof(val))
			panic("vDSO getrandom failed");
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	timespecsub(&end, &start, &diff);
	printf("   vdso: %lu times in %lu.%lu seconds\n", times, diff.tv_sec, diff.tv_nsec);

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (times = 0; times < TRIALS; ++times) {
		ssize_t ret = getrandom(&val, sizeof(val), 0);
		if (ret != sizeof(val))
			panic("syscall getrandom failed");
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	timespecsub(&end, &start, &diff);
	printf("syscall: %lu times in %lu.%lu seconds\n", times, diff.tv_sec, diff.tv_nsec);
}

int main(int argc, char *argv[])
{
	ensure_console();

	if (argc == 1) {
		if (unshare(CLONE_NEWTIME))
			panic("unshare(CLONE_NEWTIME)");
		if (!fork()) {
			if (execl(argv[0], argv[0], "now-in-timens"))
				panic("execl");
		}
		wait(NULL);
		poweroff();
	}

	print_banner();
	mount_filesystems();
	seed_rng();
	set_time();

	vdso_stuff();


	poweroff();

	kmod_selftests();
	enable_logging();
	clear_leaks();
	launch_tests();
	check_leaks();
	poweroff();
	return 1;
}
