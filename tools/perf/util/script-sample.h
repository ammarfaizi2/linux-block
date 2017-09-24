#ifndef __SCRIPT_SAMPLE_H
#define __SCRIPT_SAMPLE_H

struct dso;
struct symbol;

struct ssinfo {
	char	*data;
	size_t	 size;
};

struct script_symbol {
	u64		 id;
	int		 line;
	char		*file;
	int		 lnotab_size;
	unsigned char	*lnotab;
};

struct script_symbol *symbol__script_symbol(struct symbol *sym);
int dso__load_ssinfo(struct dso *dso);

#endif /* __SCRIPT_SAMPLE_H */
