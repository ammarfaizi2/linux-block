#include <linux/compiler.h>
#include <errno.h>
#include "script-sample.h"
#include "script-sample-api.h"
#include "util.h"
#include "debug.h"
#include "symbol.h"
#include "dso.h"

static int python_func__load(struct python_func *func,
			     struct dso *dso, struct symbol **psym)
{
	struct script_symbol *ssym;
	struct symbol *sym;

	*psym = sym = symbol__new(func->start, func->end - func->start,
				  STB_GLOBAL, STT_FUNC, func->name);
	if (!sym)
		return -1;

	ssym = symbol__script_symbol(sym);
	ssym->id   = func->header.id;
	ssym->line = (int) func->line;

	symbols__insert(&dso->symbols, sym);
	return 0;
}

static int python_file__load(struct python_file *file,
			     struct symbol *last_sym)
{
	struct script_symbol *ssym = symbol__script_symbol(last_sym);

	if (!last_sym || file->header.id != ssym->id || ssym->file)
		return -1;

	ssym->file = strdup(file->name);
	return ssym->file ? 0 : -1;
}

static int python_line__load(struct python_line *line,
			     struct symbol *last_sym)
{
	struct script_symbol *ssym = symbol__script_symbol(last_sym);

	if (!last_sym || line->header.id != ssym->id || ssym->lnotab)
		return -1;

	ssym->lnotab_size = line->size;
	ssym->lnotab = memdup(line->lnotab, line->size);
	return ssym->lnotab ? 0 : -ENOMEM;
}

static int __dso__load_ssinfo(struct dso *dso)
{
	struct symbol *last_sym = NULL;
	void *ptr = dso->ssinfo.data;
	void *end = ptr + dso->ssinfo.size;
	int err = -1, cnt = 0;

	while (ptr < end) {
		struct python_header *hdr = ptr;

		switch (hdr->type) {
		case PYTHON_DUMP__FUNC:
			err = python_func__load(ptr, dso, &last_sym);
			cnt++;
			break;
		case PYTHON_DUMP__FILE:
			err = python_file__load(ptr, last_sym);
			break;
		case PYTHON_DUMP__LINE:
			err = python_line__load(ptr, last_sym);
			break;
		default:
			pr_err("failed: unknown event %u\n", hdr->type);
			err = -1;
			break;
		};

		ptr += hdr->size;
	}

	return err < 0 ? err : cnt;
}

int dso__load_ssinfo(struct dso *dso)
{
	int err = -EINVAL;

	if (dso->ssinfo.data)
		err = __dso__load_ssinfo(dso);

	return err;
}

struct script_symbol *symbol__script_symbol(struct symbol *sym)
{
	return ((void *) sym) - symbol_conf.script_off;
}

