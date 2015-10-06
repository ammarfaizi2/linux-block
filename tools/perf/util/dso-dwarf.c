#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dwarf.h>
#include <elfutils/libdw.h>

#include "debug.h"
#include "dso.h"
#include "symbol.h"

static struct inline_expansions *inline_expansions__new(int nr_allocated)
{
	struct inline_expansions *exps = zalloc(sizeof(*exps) + nr_allocated * sizeof(exps->entries[0]));

	if (exps)
		exps->nr_allocated = nr_allocated;

	return exps;
}

static struct inline_expansions *symbol__inline_expansions(struct symbol *sym)
{
	struct inline_expansions *exps = sym->priv;

	if (exps == NULL) {
		sym->priv = exps = inline_expansions__new(8);
	} else if (exps->nr_entries == exps->nr_allocated) {
		exps = realloc(exps, sizeof(*exps) + (exps->nr_allocated + 8) * sizeof(exps->entries[0]));
		if (exps != NULL) {
			sym->priv = exps;
			exps->nr_allocated += 8;
		}
	}

	return exps;
}

static int inline_expansion__cmp(const void *a, const void *b)
{
	const struct inline_expansion *ea = a, *eb = b;

	return ea->start - eb->start;
}

static int symbol__add_inlined_expansion(struct symbol *sym, struct map *map, Dwarf_Die *die)
{
	Dwarf_Attribute inlined_function_attr;
	ptrdiff_t offset;
	Dwarf_Addr start, end, base, abstract_origin_offset;
	Dwarf_Die abstract_origin_die;
	const char *inline_name;
	struct inline_expansions *exps = NULL;
	struct inline_expansion *exp;
	u64 symbol_start;

	if (dwarf_attr(die, DW_AT_abstract_origin, &inlined_function_attr) == NULL) {
		pr_debug2("%s: dwarf_attr failed for %s\n", __func__, sym->name);
		return -1;
	}

	if (dwarf_formref_die(&inlined_function_attr, &abstract_origin_die) == NULL) {
		pr_debug2("%s: dwarf_formref_die failed for %s\n", __func__, sym->name);
		return -1;
	}

	abstract_origin_offset = dwarf_dieoffset(&abstract_origin_die);
	inline_name = dwarf_diename(&abstract_origin_die);

	start = 0;
	end   = 0;

	if (dwarf_lowpc(die, &start))
		start = 0;
	if (dwarf_highpc(die, &end))
		end = 0;

	pr_debug2("%s: name=%s(aoo=%#" PRIx64 "(%s))", __func__, sym->name, abstract_origin_offset, inline_name);
	symbol_start = map->unmap_ip(map, sym->start);

	if (end != start) {
		pr_debug2(", start=%#" PRIx64 ", end=%#" PRIx64 "\n", start, end);
		exps = symbol__inline_expansions(sym);
		if (exps == NULL) {
out_fail_inline_expansions:
			pr_debug2("%s: symbol__inline_expansions failed for %s\n", __func__, sym->name);
			return 0;
		}

		exp = &exps->entries[exps->nr_entries++];
		exp->start = start - symbol_start;
		exp->end = end - symbol_start;
		exp->name = strdup(inline_name); /* FIXME: This should be reused by all places using this inline */
		return 0;
	}

	offset = 0;

	while (1) {
		offset = dwarf_ranges(die, offset, &base, &start, &end);
		if (offset == 0)
			break;
		if (offset == -1) {
			pr_debug2("\n\tERROR!");
			break;
		}
		pr_debug2("\n\tstart=%#" PRIx64 ", end=%#" PRIx64, start, end);
		exps = symbol__inline_expansions(sym);
		if (exps == NULL)
			goto out_fail_inline_expansions;

		exp = &exps->entries[exps->nr_entries++];
		exp->start = start - symbol_start;
		exp->end = end - symbol_start;
		exp->name = strdup(inline_name); /* FIXME: This should be reused by all places using this inline */
	}

	if (exps != NULL)
		qsort(exps->entries, exps->nr_entries, sizeof(*exp), inline_expansion__cmp);

	pr_debug2("\n");
	return 0;
}

static int map__load_inline_expansions_cb(Dwarf_Die *die, void *arg)
{
	int err = 0;
	struct map *map = arg;
	const char *name = dwarf_diename(die);
	struct symbol *sym;
	Dwarf_Die child;
	Dwarf_Addr start;
	u64 mapped_start;

	pr_debug2("%s@", name);

	if (dwarf_lowpc(die, &start) < 0) {
		pr_debug2(" couldn't get the start of this function!\n");
		return 0;
	}

	pr_debug2("@%#" PRIx64 " ", start);

	mapped_start = map->map_ip(map, start);
	sym = map__find_symbol(map, mapped_start, NULL);
	if (sym == NULL) {
		pr_debug2(" not found in dso!\n");
		return 0;
	}

	pr_debug2(" == %s@%#" PRIx64 "(%#" PRIx64 ")\n", sym->name, sym->start, map->unmap_ip(map, mapped_start));

	if (sym->priv != NULL) /* Already loaded */
		return 0;

	if (!dwarf_haschildren(die) || dwarf_child(die, &child) != 0)
		return 0;

	die = &child;
	do {
		switch (dwarf_tag(die)) {
		case DW_TAG_inlined_subroutine:
			err = symbol__add_inlined_expansion(sym, map, die);
			if (err)
				break;
			break;
		default:
			/*
			 * No use for the other tags for now.
			 */
			continue;
		}
	} while (dwarf_siblingof(die, die) == 0);

	return err;
}

#if 0
static size_t symbol__fprintf_inline_expansions(struct symbol *sym, FILE *fp)
{
	struct inline_expansions *exps = sym->priv;
	size_t ret = symbol__fprintf(sym, fp);
	u32 i;

	if (exps == NULL)
		goto out;

	for (i = 0; i < exps->nr_entries; ++i) {
		struct inline_expansion *exp = &exps->entries[i];

		ret += fprintf(fp, "  %#x-%#x -> %s\n", exp->start, exp->end, exp->name);
	}
out:
	return ret;
}

static size_t dso__fprintf_inline_expansions(struct dso *dso, FILE *fp)
{
	struct rb_node *nd;
	size_t ret = 0;

	for (nd = rb_first(&dso->symbols[MAP__FUNCTION]); nd; nd = rb_next(nd)) {
		struct symbol *pos = rb_entry(nd, struct symbol, rb_node);
		ret += symbol__fprintf_inline_expansions(pos, fp);
	}

	return ret;
}
#endif

/*
 * FIXME: This really shouldn't be a map operation, as DSOs should have the addresses
 * 	  that are on the symtab they came from, not some adjusted crap that really
 * 	  should be done via the map struct. But as of now, for instance, vmlinux is
 * 	  being adjusted because we somehow decided to set the start of the kernel
 * 	  map to be _stext... Investigate.
 */
int map__load_inline_expansions(struct map *map)
{
	Dwarf_Off off = 0;
	size_t cuhl;
	Dwarf_Off noff;
	Dwarf *dbg;
	const char *filename = map->dso->long_name;
	int fd, err = -1;

	if (map->dso->inline_expansions_loaded)
		return 0;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		pr_debug("%s: failed to open %s\n", __func__, filename);
		goto out;
	}

	dbg = dwarf_begin(fd, DWARF_C_READ);
	if (dbg == NULL) {
		pr_debug("%s: failed to open %s\n", __func__, filename);
		goto out_close;
	}

	while (dwarf_nextcu(dbg, off, &noff, &cuhl, NULL, NULL, NULL) == 0) {
		Dwarf_Die die_mem;
		Dwarf_Die *die = dwarf_offdie(dbg, off + cuhl, &die_mem);
		/* Explicitly stop in the callback and then resume each time.  */
		ptrdiff_t doff = 0;

		if (die == NULL) {
			pr_debug("%s: dwarf_offdie failed!\n", __func__);
			goto out_close;
		}

		do {
			doff = dwarf_getfuncs(die, map__load_inline_expansions_cb, map, doff);
			if (dwarf_errno() != 0)
				pr_debug("dwarf_getfuncs(%s): %s", filename, dwarf_errmsg(-1));
		} while (doff != 0);

		off = noff;
	}

	dwarf_end(dbg);

	map->dso->inline_expansions_loaded = true;
	err = 0;
out_close:
	close(fd);
out:
	return err;
}
