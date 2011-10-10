/*
 * update_jump_label.h
 *
 * This code was based off of code from recordmcount.c written by
 * Copyright 2009 John F. Reiser <jreiser@BitWagon.com>.  All rights reserved.
 *
 * The original code had the same algorithms for both 32bit
 * and 64bit ELF files, but the code was duplicated to support
 * the difference in structures that were used. This
 * file creates a macro of everything that is different between
 * the 64 and 32 bit code, such that by including this header
 * twice we can create both sets of functions by including this
 * header once with UPDATE_JUMP_LABEL_64 undefined, and again with
 * it defined.
 *
 * Copyright 2010 Steven Rostedt <srostedt@redhat.com>, Red Hat Inc.
 *
 * Licensed under the GNU General Public License, version 2 (GPLv2).
 */

#undef EBITS
#undef _w

#ifdef UPDATE_JUMP_LABEL_64
# define EBITS			64
# define _w			w8
#else
# define EBITS			32
# define _w			w
#endif

#define _FBITS(x, e)	x##e
#define FBITS(x, e)	_FBITS(x, e)
#define FUNC(x)		FBITS(x, EBITS)

#undef Elf_Ehdr
#undef Elf_Shdr
#undef Elf_Rel
#undef Elf_Rela
#undef Elf_Sym
#undef ELF_R_SYM
#undef ELF_R_TYPE

#define __ATTACH(x, y, z)	x##y##z
#define ATTACH(x, y, z)		__ATTACH(x, y, z)

#define Elf_Ehdr	ATTACH(Elf, EBITS, _Ehdr)
#define Elf_Shdr	ATTACH(Elf, EBITS, _Shdr)
#define Elf_Rel		ATTACH(Elf, EBITS, _Rel)
#define Elf_Rela	ATTACH(Elf, EBITS, _Rela)
#define Elf_Sym		ATTACH(Elf, EBITS, _Sym)
#define uint_t		ATTACH(uint, EBITS, _t)
#define ELF_R_SYM	ATTACH(ELF, EBITS, _R_SYM)
#define ELF_R_TYPE	ATTACH(ELF, EBITS, _R_TYPE)

#undef get_shdr
#define get_shdr(ehdr) ((Elf_Shdr *)(_w((ehdr)->e_shoff) + (void *)(ehdr)))

#undef get_section_loc
#define get_section_loc(ehdr, shdr)(_w((shdr)->sh_offset) + (void *)(ehdr))

/* Find relocation section hdr for a given section */
static const Elf_Shdr *
FUNC(find_relhdr)(const Elf_Ehdr *ehdr, const Elf_Shdr *shdr)
{
	const Elf_Shdr *shdr0 = get_shdr(ehdr);
	int nhdr = w2(ehdr->e_shnum);
	const Elf_Shdr *hdr;
	int i;

	for (hdr = shdr0, i = 0; i < nhdr; hdr = &shdr0[++i]) {
		if (w(hdr->sh_type) != SHT_REL &&
		    w(hdr->sh_type) != SHT_RELA)
			continue;

		/*
		 * The relocation section's info field holds
		 * the section index that it represents.
		 */
		if (shdr == &shdr0[w(hdr->sh_info)])
			return hdr;
	}
	return NULL;
}

/* Find a section headr based on name and type */
static const Elf_Shdr *
FUNC(find_shdr)(const Elf_Ehdr *ehdr, const char *name, uint_t type)
{
	const Elf_Shdr *shdr0 = get_shdr(ehdr);
	const Elf_Shdr *shstr = &shdr0[w2(ehdr->e_shstrndx)];
	const char *shstrtab = (char *)get_section_loc(ehdr, shstr);
	int nhdr = w2(ehdr->e_shnum);
	const Elf_Shdr *hdr;
	const char *hdrname;
	int i;

	for (hdr = shdr0, i = 0; i < nhdr; hdr = &shdr0[++i]) {
		if (w(hdr->sh_type) != type)
			continue;

		/* If we are just looking for a section by type (ie. SYMTAB) */
		if (!name)
			return hdr;

		hdrname = &shstrtab[w(hdr->sh_name)];
		if (strcmp(hdrname, name) == 0)
			return hdr;
	}
	return NULL;
}

static void
FUNC(section_update)(const Elf_Ehdr *ehdr, const Elf_Shdr *symhdr,
		     unsigned shtype, const Elf_Rel *rel, void *data)
{
	const Elf_Shdr *shdr0 = get_shdr(ehdr);
	const Elf_Shdr *targethdr;
	const Elf_Rela *rela;
	const Elf_Sym *syment;
	uint_t offset = _w(rel->r_offset);
	uint_t info = _w(rel->r_info);
	uint_t sym = ELF_R_SYM(info);
	uint_t type = ELF_R_TYPE(info);
	uint_t addend;
	uint_t targetloc;

	if (shtype == SHT_RELA) {
		rela = (const Elf_Rela *)rel;
		addend = _w(rela->r_addend);
	} else
		addend = _w(*(int *)(data + offset));

	syment = (const Elf_Sym *)get_section_loc(ehdr, symhdr);
	targethdr = &shdr0[w2(syment[sym].st_shndx)];
	targetloc = _w(targethdr->sh_offset);

	/* TODO, need a separate function for all archs */
	if (type != R_386_32)
		die(NULL, "Arch relocation type %d not supported", type);

	targetloc += addend;

	*(uint_t *)(data + offset) = targetloc;
}

/* Overall supervision for Elf32 ET_REL file. */
static void
FUNC(do_func)(Elf_Ehdr *ehdr, char const *const fname, unsigned const reltype)
{
	const Elf_Shdr *jlshdr;
	const Elf_Shdr *jlrhdr;
	const Elf_Shdr *symhdr;
	const Elf_Rel *rel;
	unsigned size;
	unsigned cnt;
	unsigned i;
	uint_t type;
	void *jdata;
	void *data;

	jlshdr = FUNC(find_shdr)(ehdr, "__jump_table", SHT_PROGBITS);
	if (!jlshdr)
		return;

	jlrhdr = FUNC(find_relhdr)(ehdr, jlshdr);
	if (!jlrhdr)
		return;

	/*
	 * Create and fill in the __jump_table section and use it to
	 * find the offsets into the text that we want to update.
	 * We create it so that we do not depend on the order of the
	 * relocations, and use the table directly, as it is broken
	 * up into sections.
	 */
	size = _w(jlshdr->sh_size);
	data = umalloc(size);

	jdata = (void *)get_section_loc(ehdr, jlshdr);
	memcpy(data, jdata, size);

	cnt = _w(jlrhdr->sh_size) / w(jlrhdr->sh_entsize);

	rel = (const Elf_Rel *)get_section_loc(ehdr, jlrhdr);

	/* Is this as Rel or Rela? */
	type = w(jlrhdr->sh_type);

	symhdr = FUNC(find_shdr)(ehdr, NULL, SHT_SYMTAB);

	for (i = 0; i < cnt; i++) {
		FUNC(section_update)(ehdr, symhdr, type, rel, data);
		rel = (void *)rel + w(jlrhdr->sh_entsize);
	}

	/*
	 * This is specific to x86. The jump_table is stored in three
	 * long words. The first is the location of the jmp target we
	 * must update.
	 */
	cnt = size / sizeof(uint_t);

	for (i = 0; i < cnt; i += 3)
		make_nop((void *)ehdr, *(uint_t *)(data + i * sizeof(uint_t)));

	free(data);
}
