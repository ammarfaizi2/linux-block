#ifndef __SCRIPT_SAMPLE_API_H
#define __SCRIPT_SAMPLE_API_H

#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

struct python_header {
	u32	size;
	u32	type;
	u64	id;
};

enum {
	PYTHON_DUMP__FUNC	= 1,
	PYTHON_DUMP__FILE	= 2,
	PYTHON_DUMP__LINE	= 3,
	PYTHON_DUMP__STACK	= 4,
};

struct python_func {
	struct python_header	header;
	u64			start;
	u64			end;
	u64			line;
	char			name[0];
};

struct python_file {
	struct python_header	header;
	char			name[0];
};

struct python_line {
	struct python_header	header;
	u64			size;
	unsigned char		lnotab[0];
};

struct python_stack {
	struct python_header	header;
	u64			cnt;
	u64			data[0];
};

#endif /* __SCRIPT_SAMPLE_API_H */
