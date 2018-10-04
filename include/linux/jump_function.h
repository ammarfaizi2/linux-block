/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JUMP_FUNCTION_H
#define _LINUX_JUMP_FUNCTION_H


//// This all should be in arch/x86/include/asm

typedef long dynfunc_t;

/*
 * dynfunc_entry created for each location where a dynfunc exits
 * @code: The location of the function to dynamically change
 * @key: The way to find where the dynfunc_struct is
 */
struct dynfunc_entry {
	dynfunc_t	code;
	dynfunc_t	key;
};

struct dynfunc_struct;

int arch_assign_dynamic_function(const struct dynfunc_struct *dynfunc, void *func);

/*
 * _ADD_FUNC_ARG_0 - basis for all dynamic functions (and for zero arg functions)
 * @key: The key to find the dynfunc_struct
 * @retval: The return value of the called function
 * @def: The default function to call (set at build time)
 * @ignore: required, for void parameter
 *
 * This calls the default function but also creates a dynfunc_entry
 * in __dynfunc_table, so that it can be modified at run time to call
 * a different function.
 */
#define _ADD_FUNC_ARG_0(key, retval, def, ignore)			\
	"1: call " #def "\n\t"				\
	"movq %%rax, %[ret]\n\t"			\
	".pushsection __dynfunc_table, \"aw\" \n\t"	\
	".balign 8\n\t"					\
	".quad 1b, %c1 \n\t"				\
	".popsection \n\t"				\
	: [ret] "=rax" (retval) : "i" (key), "i" (def)

/*
 * _ADD_FUNC_ARG_1 - same as _ADD_FUNC_ARG_0 but with 1 argument.
 */
#define _ADD_FUNC_ARG_1(key, ret, def, a)		\
	"movq	(%[arg1]), %%rdi \n\t"			\
	_ADD_FUNC_ARG_0(key, ret, def, ignore),		\
	[arg1] "r" ((long)&a)

#define _ADD_FUNC_ARG_2(key, ret, def, a, b)		\
	"movq	(%[arg2]), %%rsi \n\t"		\
	_ADD_FUNC_ARG_1(key, ret, def, a),		\
	[arg2] "r" ((long)&b)

#define _ADD_FUNC_ARG_3(key, ret, def, a, b, c)	\
	"movq	(%[arg3]), %%rdx \n\t"		\
	_ADD_FUNC_ARG_2(key, ret, def, a, b),	\
	[arg3] "r" ((long)&c)

#define _ADD_FUNC_ARG_4(key, ret, def, a, b, c, d)	\
	"movq	(%[arg4]), %%rcx \n\t"		\
	_ADD_FUNC_ARG_3(key, ret, def, a, b, c),	\
	[arg4] "r" ((long)&d)

#define _ADD_FUNC_ARG_5(key, ret, def, a, b, c, d, e)	\
	"movq	(%[arg5]), %%r8 \n\t"		\
	_ADD_FUNC_ARG_4(key, ret, def, a, b, c, d),	\
	[arg5] "r" ((long)&e)

#define _ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)	\
	"movq	(%[arg6]), %%r9 \n\t"				\
	_ADD_FUNC_ARG_5(key, ret, def, a, b, c, d, e),		\
	[arg6] "r" ((long)&f)

#define _ADD_FUNC_ARG_7(key, ret, def, a, b, c, d, e, f, f1)	\
	_ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)

#define _ADD_FUNC_ARG_8(key, ret, def, a, b, c, d, e, f, f1, f2)	\
	_ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)

#define _ADD_FUNC_ARG_9(key, ret, def, a, b, c, d, e, f, f1, f2, f3)	\
	_ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)

#define _ADD_FUNC_ARG_10(key, ret, def, a, b, c, d, e, f, f1, f2, f3, f4)	\
	_ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)

#define _ADD_FUNC_ARG_11(key, ret, def, a, b, c, d, e, f, f1, f2, f3, f4, f5)	\
	_ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)

#define _ADD_FUNC_ARG_12(key, ret, def, a, b, c, d, e, f, f1, f2, f3, f4, f5, f6)	\
	_ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)

#define _ADD_FUNC_ARG_13(key, ret, def, a, b, c, d, e, f, f1, f2, f3, f4, f5, f6, f7) \
	_ADD_FUNC_ARG_6(key, ret, def, a, b, c, d, e, f)


#define _ADD_REG_0
#define _ADD_REG_1 , "rdi"
#define _ADD_REG_2 _ADD_REG_1 , "rsi"
#define _ADD_REG_3 _ADD_REG_2 , "rdx"
#define _ADD_REG_4 _ADD_REG_3 , "rcx"
#define _ADD_REG_5 _ADD_REG_4 , "r8"
#define _ADD_REG_6 _ADD_REG_5 , "r9"

#define _ADD_REG_7 _ADD_REG_6
#define _ADD_REG_8 _ADD_REG_6
#define _ADD_REG_9 _ADD_REG_6
#define _ADD_REG_10 _ADD_REG_6
#define _ADD_REG_11 _ADD_REG_6
#define _ADD_REG_12 _ADD_REG_6
#define _ADD_REG_13 _ADD_REG_6

/*
 * arch_jump_func - Create the dynamic function call
 * @n: Number of arguments
 * @key: The key to find the dynfunc_struct
 * @ret: The return value of the called function
 * @def: The default function to call (set at build time)
 */
#define arch_jump_func(n, key, ret, def, ...)				\
	asm volatile(							\
		_ADD_FUNC_ARG_##n(key, ret, def, __VA_ARGS__)		\
		: "memory" _ADD_REG_##n )

//////////////// The below should be in include/linux

#ifndef PARAMS
#define PARAMS(x...) x
#endif

#ifndef ARGS
#define ARGS(x...) x
#endif

struct dynfunc_struct {
	const void		*func;
	struct dynfunc_entry	entry;
};

int assign_dynamic_function(const struct dynfunc_struct *dynfunc, void *func);

#define __jump_func(n, key, def, ...) \
	({					\
	long __ret;				\
	arch_jump_func(n, key, __ret, def, __VA_ARGS__);	\
	__ret; })

#define jump_func(key, def, ...) \
	__jump_func(COUNT_ARGS(__VA_ARGS__), key, def, __VA_ARGS__)

/*
 * DECLARE_DYNAMIC_FUNCTION - Declaration to create a dynamic function call
 * @name: The name of the function call to create
 * @proto: The proto-type of the function (up to 4 args)
 * @args: The arguments used by @proto
 *
 * This macro creates the function that can by used to create a dynamic
 * function call later. It also creates the function to modify what is
 * called:
 *
 *   dynfunc_[name](args);
 *
 * This is placed in the code where the dynamic function should be called
 * from.
 *
 *   assign_dynamic_function_[name](func);
 *
 * This is used to make the dynfunc_[name]() call a different function.
 * It will then call (func) instead.
 *
 * This must be added in a header for users of the above two functions.
 */
#define DECLARE_DYNAMIC_FUNCTION(name, proto, args)			\
	extern struct dynfunc_struct ___dyn_func__##name;		\
	extern int ___dyn_func__##name##__func(proto);			\
	static inline int assign_dynamic_function_##name(int(*func)(proto)) { \
		return assign_dynamic_function(&___dyn_func__##name, func); \
	}								\
	static __always_inline int dynfunc_##name(proto) {		\
		return jump_func(&___dyn_func__##name.entry.key,	\
				 ___dyn_func__##name##__func, args);	\
	}

/*
 * DEFINE_DYNAMIC_FUNCTION - Define the dynamic function and default
 * @name: The name of the function call to create
 * @def: The default function to call
 * @proto: The proto-type of the function (up to 4 args)
 *
 * Must be placed in a C file.
 *
 * This sets up the dynamic function that other places may call
 * dynfunc_[name]().
 *
 * It defines the default function that the dynamic function will start
 * out calling at boot up.
 */
#define DEFINE_DYNAMIC_FUNCTION(name, def, proto)			\
	int ___dyn_func__##name##__func(proto) __used __alias(def);	\
	struct dynfunc_struct ___dyn_func__##name __used = {		\
		.func		= def,					\
	}

extern struct dynfunc_entry __start___dynfunc_table[];
extern struct dynfunc_entry __stop___dynfunc_table[];

#endif	/*  _LINUX_JUMP_FUNCTION_H */
