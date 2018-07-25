/* Filesystem parameter parser.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/export.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/namei.h>
#include <linux/bsearch.h>
#include "internal.h"

static const struct constant_table bool_names[] = {
	{ "0",		false },
	{ "1",		true },
	{ "false",	false },
	{ "no",		false },
	{ "true",	true },
	{ "yes",	true },
};

static int cmp_constant(const void *name, const void *entry)
{
	const struct constant_table *e = entry;
	return strcmp(name, e->name);
}

/**
 * lookup_constant - Look up a constant by name in an ordered table
 * @tbl: The table of constants to search.
 * @tbl_size: The size of the table.
 * @name: The name to look up.
 * @not_found: The value to return if the name is not found.
 */
int __lookup_constant(const struct constant_table *tbl, size_t tbl_size,
		      const char *name, int not_found)
{
	const struct constant_table *e;

	e = bsearch(name, tbl, tbl_size, sizeof(tbl[0]), cmp_constant);
	if (!e)
		return not_found;
	return e->value;
}
EXPORT_SYMBOL(__lookup_constant);

/*
 * fs_parse - Parse a filesystem configuration parameter
 * @fc: The filesystem context to log errors through.
 * @desc: The parameter description to use.
 * @param: The parameter.
 * @result: Where to place the result of the parse
 *
 * Parse a filesystem configuration parameter and attempt a conversion for a
 * simple parameter for which this is requested.  If successful, the determined
 * parameter ID is placed into @result->key, the desired type is indicated in
 * @result->t and any converted value is placed into an appropriate member of
 * the union in @result.
 *
 * The function returns 1 if the parameter was matched, 0 if it wasn't matched
 * and @desc->ignore_unknown indicated that unknown parameters are okay and
 * -EINVAL if there was a conversion issue or the parameter wasn't recognised
 * and unknowns aren't okay.
 */
int fs_parse(struct fs_context *fc,
	     const struct fs_parameter_description *desc,
	     struct fs_parameter *param,
	     struct fs_parse_result *result)
{
	int ret, k, i, b;

	result->has_value = !!param->string;

	k = __lookup_constant(desc->keys, desc->nr_keys, param->key,
			      -EAGAIN);
	if (k == -EAGAIN) {
		/* If we didn't find something that looks like "noxxx", see if
		 * "xxx" takes the "no"-form negative - but only if there
		 * wasn't an value.
		 */
		if (result->has_value)
			goto unknown_parameter;
		if (param->key[0] != 'n' || param->key[1] != 'o' || !param->key[2])
			goto unknown_parameter;

		k = __lookup_constant(desc->keys, desc->nr_keys,
				      param->key + 2, -EAGAIN);
		if (k == -EAGAIN)
			goto unknown_parameter;
		if (!(desc->specs[k].flags & fs_param_neg_with_no))
			goto unknown_parameter;
		result->key = k;
		result->uint_32 = 0;
		result->negated = true;
		goto okay;
	}

	result->key = k;
	result->negated = false;
	if (result->key == fsconfig_key_removed)
		return invalf(fc, "%s: Unsupported parameter name '%s'",
			      desc->name, param->key);

	result->t = desc->specs[result->key];
	if (result->t.flags & fs_param_deprecated)
		warnf(fc, "%s: Deprecated parameter '%s'",
		      desc->name, param->key);

	/* Certain parameter types only take a string and convert it. */
	switch (result->t.type) {
	case __fs_param_wasnt_defined:
		return -EINVAL;
	case fs_param_is_u32:
	case fs_param_is_u32_octal:
	case fs_param_is_u32_hex:
	case fs_param_is_s32:
	case fs_param_is_enum:
	case fs_param_is_string:
		if (param->type != fs_value_is_string)
			goto bad_value;
		if (!result->has_value) {
			if (desc->specs[k].flags & fs_param_v_optional)
				goto okay;
			goto bad_value;
		}
		/* Fall through */
	default:
		break;
	}

	/* Try to turn the type we were given into the type desired by the
	 * parameter and give an error if we can't.
	 */
	switch (result->t.type) {
	case fs_param_takes_no_value:
		if (param->type != fs_value_is_flag &&
		    (param->type != fs_value_is_string || result->has_value))
			return invalf(fc, "%s: Unexpected value for '%s'",
				      desc->name, param->key);
		result->boolean = true;
		goto okay;

	case fs_param_is_bool:
		switch (param->type) {
		case fs_value_is_flag:
			result->boolean = true;
			goto okay;
		case fs_value_is_string:
			if (param->size == 0) {
				result->boolean = true;
				goto okay;
			}
			b = lookup_constant(bool_names, param->string, -1);
			if (b == -1)
				goto bad_value;
			result->boolean = b;
			goto okay;
		default:
			goto bad_value;
		}

	case fs_param_is_u32:
		ret = kstrtouint(param->string, 0, &result->uint_32);
		goto maybe_okay;
	case fs_param_is_u32_octal:
		ret = kstrtouint(param->string, 8, &result->uint_32);
		goto maybe_okay;
	case fs_param_is_u32_hex:
		ret = kstrtouint(param->string, 16, &result->uint_32);
		goto maybe_okay;
	case fs_param_is_s32:
		ret = kstrtoint(param->string, 0, &result->int_32);
		goto maybe_okay;

	case fs_param_is_enum:
		for (i = 0; i < desc->nr_enums; i++) {
			if (desc->enums[i].param_id == result->key &&
			    strcmp(desc->enums[i].name, param->string) == 0) {
				result->uint_32 = desc->enums[i].value;
				goto okay;
			}
		}
		goto bad_value;

	case fs_param_is_string:
		goto okay;
	case fs_param_is_blob:
		if (param->type != fs_value_is_blob)
			goto bad_value;
		goto okay;

	case fs_param_is_fd: {
		if (param->type != fs_value_is_file)
			goto bad_value;
		goto okay;
	}

	case fs_param_is_blockdev:
	case fs_param_is_path:
		goto okay;
	default:
		BUG();
	}

maybe_okay:
	if (ret < 0)
		goto bad_value;
okay:
	return 1;

bad_value:
	return invalf(fc, "%s: Bad value for '%s'", desc->name, param->key);
unknown_parameter:
	if (desc->ignore_unknown)
		return 0;
	if (desc->no_source && strcmp(param->key, "source") == 0)
		return 0; /* The source parameter is special */
	return invalf(fc, "%s: Unknown parameter '%s'", desc->name, param->key);
}
EXPORT_SYMBOL(fs_parse);

/**
 * fs_lookup_param - Look up a path referred to by a parameter
 * @fc: The filesystem context to log errors through.
 * @desc: The parameter description that was used
 * @key: The name of the parameter.
 * @value: The supplied value for the parameter
 * @result: The result of the parse from a previous call to fs_parse()
 * @_path: The result of the lookup
 */
int fs_lookup_param(struct fs_context *fc,
		    const struct fs_parameter_description *desc,
		    struct fs_parameter *param,
		    struct fs_parse_result *result,
		    struct path *_path)
{
	struct filename *f;
	unsigned int flags = 0;
	bool put_f;
	int ret;

	switch (param->type) {
	case fs_value_is_string:
		f = getname_kernel(param->string);
		if (IS_ERR(f))
			return PTR_ERR(f);
		put_f = true;
		break;
	case fs_value_is_filename_empty:
		flags = LOOKUP_EMPTY;
		/* Fall through */
	case fs_value_is_filename:
		f = param->name;
		put_f = false;
		break;
	default:
		return invalf(fc, "%s: '%s' not usable as path",
			      desc->name, param->key);
	}

	ret = filename_lookup(param->dirfd, f, flags, _path, NULL);
	if (put_f)
		putname(f);
	if (ret < 0) {
		errorf(fc, "%s: Lookup failure for '%s'",
		       desc->name, param->key);
		return ret;
	}

	if (result->t.type == fs_param_is_blockdev &&
	    !S_ISBLK(d_real_inode(_path->dentry)->i_mode)) {
		path_put(_path);
		_path->dentry = NULL;
		_path->mnt = NULL;
		errorf(fc, "%s: Non-blockdev passed to '%s'",
		       desc->name, param->key);
		return -ENOTBLK;
	}

	return 0;
}
EXPORT_SYMBOL(fs_lookup_param);

#ifdef CONFIG_VALIDATE_FS_PARSER
/**
 * validate_constant_table - Validate a constant table
 * @tbl: The constant table to validate.
 * @tbl_size: The size of the table.
 * @low: The lowest permissible value.
 * @high: The highest permissible value.
 * @special: One special permissible value outside of the range.
 */
bool validate_constant_table(const struct constant_table *tbl, size_t tbl_size,
			     int low, int high, int special)
{
	size_t i;
	bool good = true;

	if (tbl_size == 0) {
		pr_warn("VALIDATE C-TBL: Empty\n");
		return true;
	}

	for (i = 0; i < tbl_size; i++) {
		if (!tbl[i].name) {
			pr_err("VALIDATE C-TBL[%zu]: Null\n", i);
			good = false;
		} else if (i > 0 && tbl[i - 1].name) {
			int c = strcmp(tbl[i-1].name, tbl[i].name);

			if (c == 0) {
				pr_err("VALIDATE C-TBL[%zu]: Duplicate %s\n",
				       i, tbl[i].name);
				good = false;
			}
			if (c > 0) {
				pr_err("VALIDATE C-TBL[%zu]: Missorted %s>=%s\n",
				       i, tbl[i-1].name, tbl[i].name);
				good = false;
			}
		}

		if (tbl[i].value != special &&
		    (tbl[i].value < low || tbl[i].value > high)) {
			pr_err("VALIDATE C-TBL[%zu]: %s->%d const out of range (%d-%d)\n",
			       i, tbl[i].name, tbl[i].value, low, high);
			good = false;
		}
	}

	if (!good)
		dump_stack();
	return good;
}

/**
 * fs_validate_description - Validate a parameter description
 * @desc: The parameter description to validate.
 */
bool fs_validate_description(const struct fs_parameter_description *desc)
{
	const char *name = desc->name;
	bool good = true, dump = true, enums = false;
	int i, j;

	if (!name[0]) {
		pr_err("Parser: No name\n");
		name = "Unknown";
		good = false;
	}

	if (desc->nr_params) {
		if (!desc->specs) {
			pr_err("%s: Parser: Missing types table\n", name);
			good = false;
			goto no_specs;
		}

		for (i = 0; i < desc->nr_params; i++) {
			enum fs_parameter_type t = desc->specs[i].type;
			if (t == __fs_param_wasnt_defined) {
				pr_err("%s: Parser: [%u] Undefined type\n",
				       name, i);
				good = false;
			} else if (t >= nr__fs_parameter_type) {
				pr_err("%s: Parser: [%u] Bad type %u\n",
				       name, i, t);
				good = false;
			} else if (t == fs_param_is_enum) {
				enums = true;
			}
		}
	}

no_specs:
	if (desc->nr_keys) {
		if (!desc->nr_params) {
			pr_err("%s: Parser: %u keys but 0 params\n",
			       name, desc->nr_keys);
			good = false;
			goto no_keys;
		}
		if (!desc->keys) {
			pr_err("%s: Parser: Missing keys table\n", name);
			good = false;
			goto no_keys;
		}

		if (!validate_constant_table(desc->keys, desc->nr_keys,
					     0, desc->nr_params - 1,
					     fsconfig_key_removed)) {
			pr_err("%s: Parser: Bad keys table\n", name);
			good = false;
			dump = false;
		}

		/* The "source" key is used to convey the device/source
		 * information.
		 */
		if (__lookup_constant(desc->keys, desc->nr_keys,
				      "source", -1234) == -1234) {
			if (!desc->no_source) {
				pr_err("%s: Parser: Source key, but marked no_source\n",
				       name);
				good = false;
			}
		} else {
			if (desc->no_source) {
				pr_err("%s: Parser: Marked no_source, but no source key\n",
				       name);
				good = false;
			}
		}
	}

no_keys:
	if (desc->nr_enums) {
		if (!enums) {
			pr_err("%s: Parser: Enum table but no enum-type values\n",
			       name);
			good = false;
			goto no_enums;
		}
		if (!desc->enums) {
			pr_err("%s: Parser: Missing enums table\n", name);
			good = false;
			goto no_enums;
		}

		for (j = 0; j < desc->nr_enums; j++) {
			const struct fs_parameter_enum *e = &desc->enums[j];

			if (!e->name[0]) {
				pr_err("%s: Parser: e[%u] no name\n", name, j);
				good = false;
			}
			if (e->param_id >= desc->nr_params) {
				pr_err("%s: Parser: e[%u] bad param %u\n",
				       name, j, e->param_id);
				good = false;
			}
			if (desc->specs[e->param_id].type != fs_param_is_enum) {
				pr_err("%s: Parser: e[%u] enum val for non-enum type %u\n",
				       name, j, e->param_id);
				good = false;
			}
		}

		for (i = 0; i < desc->nr_params; i++) {
			if (desc->specs[i].type != fs_param_is_enum)
				continue;
			for (j = 0; j < desc->nr_enums; j++)
				if (desc->enums[j].param_id == i)
					break;
			if (j == desc->nr_enums) {
				pr_err("%s: Parser: t[%u] enum with no vals\n",
				       name, i);
				good = false;
			}
		}
	} else {
		if (enums) {
			pr_err("%s: Parser: enum-type values, but no enum table\n",
			       name);
			good = false;
			goto no_enums;
		}
	}

no_enums:
	if (!good && dump)
		dump_stack();
	return good;
}
#endif /* CONFIG_VALIDATE_FS_PARSER */
