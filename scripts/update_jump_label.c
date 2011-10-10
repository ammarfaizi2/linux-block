/*
 * update_jump_label.c: replace jmps with nops at compile time.
 * Copyright 2010 Steven Rostedt <srostedt@redhat.com>, Red Hat Inc.
 *  Parsing of the elf file was influenced by recordmcount.c
 *  originally written by and copyright to John F. Reiser <jreiser@BitWagon.com>.
 */

/*
 * Note, this code is originally designed for x86, but may be used by
 * other archs to do the nop updates at compile time instead of at boot time.
 * X86 uses this as an optimization, as jmps can be either 2 bytes or 5 bytes.
 * Inserting a 2 byte where possible helps with both CPU performance and
 * icache strain.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <getopt.h>
#include <elf.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static int fd_map;	/* File descriptor for file being modified. */
static struct stat sb;	/* Remember .st_size, etc. */
static int mmap_failed; /* Boolean flag. */

static void die(const char *err, const char *fmt, ...)
{
	va_list ap;

	if (err)
		perror(err);

	if (fmt) {
		va_start(ap, fmt);
		fprintf(stderr, "Fatal error:  ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		va_end(ap);
	}

	exit(1);
}

static void usage(char **argv)
{
	char *arg = argv[0];
	char *p = arg + strlen(arg);

	while (p >= arg && *p != '/')
		p--;
	p++;

	printf("usage: %s file\n"
	       "\n", p);
	exit(-1);
}

/* w8rev, w8nat, ...: Handle endianness. */

static uint64_t w8rev(uint64_t const x)
{
	return   ((0xff & (x >> (0 * 8))) << (7 * 8))
	       | ((0xff & (x >> (1 * 8))) << (6 * 8))
	       | ((0xff & (x >> (2 * 8))) << (5 * 8))
	       | ((0xff & (x >> (3 * 8))) << (4 * 8))
	       | ((0xff & (x >> (4 * 8))) << (3 * 8))
	       | ((0xff & (x >> (5 * 8))) << (2 * 8))
	       | ((0xff & (x >> (6 * 8))) << (1 * 8))
	       | ((0xff & (x >> (7 * 8))) << (0 * 8));
}

static uint32_t w4rev(uint32_t const x)
{
	return   ((0xff & (x >> (0 * 8))) << (3 * 8))
	       | ((0xff & (x >> (1 * 8))) << (2 * 8))
	       | ((0xff & (x >> (2 * 8))) << (1 * 8))
	       | ((0xff & (x >> (3 * 8))) << (0 * 8));
}

static uint32_t w2rev(uint16_t const x)
{
	return   ((0xff & (x >> (0 * 8))) << (1 * 8))
	       | ((0xff & (x >> (1 * 8))) << (0 * 8));
}

static uint64_t w8nat(uint64_t const x)
{
	return x;
}

static uint32_t w4nat(uint32_t const x)
{
	return x;
}

static uint32_t w2nat(uint16_t const x)
{
	return x;
}

static uint64_t (*w8)(uint64_t);
static uint32_t (*w)(uint32_t);
static uint32_t (*w2)(uint16_t);

/* ulseek, uread, ...:  Check return value for errors. */

static off_t
ulseek(int const fd, off_t const offset, int const whence)
{
	off_t const w = lseek(fd, offset, whence);
	if (w == (off_t)-1)
		die("lseek", NULL);

	return w;
}

static size_t
uread(int const fd, void *const buf, size_t const count)
{
	size_t const n = read(fd, buf, count);
	if (n != count)
		die("read", NULL);

	return n;
}

static size_t
uwrite(int const fd, void const *const buf, size_t const count)
{
	size_t const n = write(fd, buf, count);
	if (n != count)
		die("write", NULL);

	return n;
}

static void *
umalloc(size_t size)
{
	void *const addr = malloc(size);
	if (addr == 0)
		die("malloc", "malloc failed: %zu bytes\n", size);

	return addr;
}

/*
 * Get the whole file as a programming convenience in order to avoid
 * malloc+lseek+read+free of many pieces.  If successful, then mmap
 * avoids copying unused pieces; else just read the whole file.
 * Open for both read and write; new info will be appended to the file.
 * Use MAP_PRIVATE so that a few changes to the in-memory ElfXX_Ehdr
 * do not propagate to the file until an explicit overwrite at the last.
 * This preserves most aspects of consistency (all except .st_size)
 * for simultaneous readers of the file while we are appending to it.
 * However, multiple writers still are bad.  We choose not to use
 * locking because it is expensive and the use case of kernel build
 * makes multiple writers unlikely.
 */
static void *mmap_file(char const *fname)
{
	void *addr;

	fd_map = open(fname, O_RDWR);
	if (fd_map < 0 || fstat(fd_map, &sb) < 0)
		die(fname, "failed to open file");

	if (!S_ISREG(sb.st_mode))
		die(NULL, "not a regular file: %s\n", fname);

	addr = mmap(0, sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE,
		    fd_map, 0);

	mmap_failed = 0;
	if (addr == MAP_FAILED) {
		mmap_failed = 1;
		addr = umalloc(sb.st_size);
		uread(fd_map, addr, sb.st_size);
	}
	return addr;
}

static void munmap_file(void *addr)
{
	if (!mmap_failed)
		munmap(addr, sb.st_size);
	else
		free(addr);
	close(fd_map);
}

static unsigned char ideal_nop5_x86_64[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
static unsigned char ideal_nop5_x86_32[5] = { 0x3e, 0x8d, 0x74, 0x26, 0x00 };
static unsigned char ideal_nop2_x86[2] = { 0x66, 0x90 };
static unsigned char *ideal_nop;

static int (*make_nop)(void *map, size_t const offset);

static int make_nop_x86(void *map, size_t const offset)
{
	unsigned char *op;
	unsigned char *nop;
	int size;

	/* Determine which type of jmp this is 2 byte or 5. */
	op = map + offset;
	switch (*op) {
	case 0xeb: /* 2 byte */
		size = 2;
		nop = ideal_nop2_x86;
		break;
	case 0xe9: /* 5 byte */
		size = 5;
		nop = ideal_nop;
		break;
	default:
		die(NULL, "Bad jump label section (bad op %x)\n", *op);
		__builtin_unreachable();
	}

	/* convert to nop */
	ulseek(fd_map, offset, SEEK_SET);
	uwrite(fd_map, nop, size);
	return 0;
}

/* 32 bit and 64 bit are very similar */
#include "update_jump_label.h"
#define UPDATE_JUMP_LABEL_64
#include "update_jump_label.h"

static int do_file(const char *fname)
{
	Elf32_Ehdr *const ehdr = mmap_file(fname);
	unsigned int reltype = 0;

	w = w4nat;
	w2 = w2nat;
	w8 = w8nat;
	switch (ehdr->e_ident[EI_DATA]) {
		static unsigned int const endian = 1;
	default:
		die(NULL, "unrecognized ELF data encoding %d: %s\n",
			ehdr->e_ident[EI_DATA], fname);
		break;
	case ELFDATA2LSB:
		if (*(unsigned char const *)&endian != 1) {
			/* main() is big endian, file.o is little endian. */
			w = w4rev;
			w2 = w2rev;
			w8 = w8rev;
		}
		break;
	case ELFDATA2MSB:
		if (*(unsigned char const *)&endian != 0) {
			/* main() is little endian, file.o is big endian. */
			w = w4rev;
			w2 = w2rev;
			w8 = w8rev;
		}
		break;
	}  /* end switch */

	if (memcmp(ELFMAG, ehdr->e_ident, SELFMAG) != 0 ||
	    w2(ehdr->e_type) != ET_REL ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT)
		die(NULL, "unrecognized ET_REL file %s\n", fname);

	switch (w2(ehdr->e_machine)) {
	default:
		die(NULL, "unrecognized e_machine %d %s\n",
		    w2(ehdr->e_machine), fname);
		break;
	case EM_386:
		reltype = R_386_32;
		make_nop = make_nop_x86;
		ideal_nop = ideal_nop5_x86_32;
		break;
	case EM_ARM:	 reltype = R_ARM_ABS32;
			 break;
	case EM_IA_64:	 reltype = R_IA64_IMM64; break;
	case EM_MIPS:	 /* reltype: e_class    */ break;
	case EM_PPC:	 reltype = R_PPC_ADDR32;   break;
	case EM_PPC64:	 reltype = R_PPC64_ADDR64; break;
	case EM_S390:    /* reltype: e_class    */ break;
	case EM_SH:	 reltype = R_SH_DIR32;                 break;
	case EM_SPARCV9: reltype = R_SPARC_64;     break;
	case EM_X86_64:
		make_nop = make_nop_x86;
		ideal_nop = ideal_nop5_x86_64;
		reltype = R_X86_64_64;
		break;
	}  /* end switch */

	switch (ehdr->e_ident[EI_CLASS]) {
	default:
		die(NULL, "unrecognized ELF class %d %s\n",
		    ehdr->e_ident[EI_CLASS], fname);
		break;
	case ELFCLASS32:
		if (w2(ehdr->e_ehsize) != sizeof(Elf32_Ehdr)
		||  w2(ehdr->e_shentsize) != sizeof(Elf32_Shdr))
			die(NULL, "unrecognized ET_REL file: %s\n", fname);

		do_func32(ehdr, fname, reltype);
		break;
	case ELFCLASS64: {
		Elf64_Ehdr *const ghdr = (Elf64_Ehdr *)ehdr;
		if (w2(ghdr->e_ehsize) != sizeof(Elf64_Ehdr)
		||  w2(ghdr->e_shentsize) != sizeof(Elf64_Shdr))
			die(NULL, "unrecognized ET_REL file: %s\n", fname);

		do_func64(ghdr, fname, reltype);
		break;
	}
	}  /* end switch */

	munmap_file(ehdr);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		usage(argv);

	return do_file(argv[1]);
}

