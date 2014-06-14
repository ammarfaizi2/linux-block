/*
 * Copyright 2014 Andy Lutomirski
 * Subject to the GNU Public License, v.2
 *
 * AT_VDSO_FINDSYM implementation
 *
 * AT_VDSO_FINDSYM is a mechanism that can be used by userspace runtimes
 * that don't want to implement a full ELF parser.  The ELF parser in
 * here cheats heavily.  It relies on the linker to do part of the work,
 * and it makes questionable assumptions about the layout of some of the
 * dynamic data structures.  Those questionable assumptions are verified
 * by vdso2c.
 */

#pragma GCC optimize ("Os")

#include <linux/elf.h>
#include <linux/compiler.h>

struct elf_hash {
	Elf64_Word nbuckets;
	Elf64_Word nchains;
	const Elf64_Word data[];
};

/*
 * These must be explicitly hidden: we need to access them via direct
 * PC-relative relocations, not through the GOT, since we have no GOT.
 */
extern const char VDSO_START[] __attribute__((visibility("hidden")));
extern const char DYN_STRTAB[] __attribute__((visibility("hidden")));
extern const Elf64_Sym DYN_SYMTAB[] __attribute__((visibility("hidden")));
extern const struct elf_hash DYN_HASH __attribute__((visibility("hidden")));
extern const Elf64_Half DYN_VERSYM[] __attribute__((visibility("hidden")));
extern const Elf64_Verdef DYN_VERDEF[] __attribute__((visibility("hidden")));

/* Straight from the ELF specification. */
static unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while (*name)
	{
		h = (h << 4) + *name++;
		if ((g = h & 0xf0000000) != 0)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

static bool strtab_matches(Elf32_Word strindex, const char *b)
{
	const char *a = &DYN_STRTAB[strindex];
	while (true) {
		if (*a != *b)
			return false;
		if (!*a)
			return true;
		a++;
		b++;
	}
}

void *__vdso_findsym(const char *name, const char *version)
{
	Elf64_Half vd_ndx;
	const Elf64_Verdef *def = DYN_VERDEF;
	Elf64_Word chain;
	const Elf64_Word *chain_next;

	/*
	 * First find the version index.  There's some documentation
	 * here: http://www.tux.org/pub/tux/eric/elf/docs/GNUvers.txt
	 */
	while(true) {
		/*
		 * Don't even bother checking the hash -- the list we're
		 * walking is too short (and, of course, the ELF version
		 * format forgot to make it a hash table.
		 */
		const Elf64_Verdaux *aux = (const Elf64_Verdaux*)
			((const char *)def + def->vd_aux);
		if ((def->vd_flags & VER_FLG_BASE) == 0
		    && strtab_matches(aux->vda_name, version)) {
			vd_ndx = def->vd_ndx;
			break;
		}

		if (def->vd_next == 0)
			return NULL;  /* No match for the version. */

		def = (const Elf64_Verdef *)((const char *)def + def->vd_next);
	}

	chain_next = &DYN_HASH.data[DYN_HASH.nbuckets];
	for (chain = DYN_HASH.data[elf_hash(name) % DYN_HASH.nbuckets];
	     chain != STN_UNDEF; chain = chain_next[chain]) {
		const Elf64_Sym *sym = &DYN_SYMTAB[chain];

		/*
		 * vdso2c will check that all relevant symbols are
		 * STB_GLOBAL, STT_FUNC and vice versa.
		 */
		if (sym->st_info == ELF_ST_INFO(STB_GLOBAL, STT_FUNC) &&
		    (DYN_VERSYM[chain] & 0x7fff) == vd_ndx &&
		    strtab_matches(sym->st_name, name)) {
			return (void *)
				((unsigned long)VDSO_START + sym->st_value);
		}
	}

	return NULL;
}
