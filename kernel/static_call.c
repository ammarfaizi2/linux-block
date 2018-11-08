/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/init.h>
#include <linux/static_call.h>
#include <linux/bug.h>
#include <linux/smp.h>
#include <linux/sort.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/processor.h>
#include <asm/sections.h>

extern struct static_call_site __start_static_call_sites[],
			       __stop_static_call_sites[];

static bool static_call_initialized;

/* mutex to protect key modules/sites */
static DEFINE_MUTEX(static_call_mutex);

static void static_call_lock(void)
{
	mutex_lock(&static_call_mutex);
}

static void static_call_unlock(void)
{
	mutex_unlock(&static_call_mutex);
}

static inline unsigned long static_call_addr(struct static_call_site *site)
{
	return (long)site->addr + (long)&site->addr;
}

static inline struct static_call_key *static_call_key(const struct static_call_site *site)
{
	return (struct static_call_key *)((long)site->key + (long)&site->key);
}

static int static_call_site_cmp(const void *_a, const void *_b)
{
	const struct static_call_site *a = _a;
	const struct static_call_site *b = _b;
	const struct static_call_key *key_a = static_call_key(a);
	const struct static_call_key *key_b = static_call_key(b);

	if (key_a < key_b)
		return -1;

	if (key_a > key_b)
		return 1;

	return 0;
}

static void static_call_site_swap(void *_a, void *_b, int size)
{
	long delta = (unsigned long)_a - (unsigned long)_b;
	struct static_call_site *a = _a;
	struct static_call_site *b = _b;
	struct static_call_site tmp = *a;

	a->addr = b->addr  - delta;
	a->key  = b->key   - delta;

	b->addr = tmp.addr + delta;
	b->key  = tmp.key  + delta;
}

static inline void static_call_sort_entries(struct static_call_site *start,
					    struct static_call_site *stop)
{
	sort(start, stop - start, sizeof(struct static_call_site),
	     static_call_site_cmp, static_call_site_swap);
}

void __static_call_update(struct static_call_key *key, void *func)
{
	struct static_call_mod *mod;
	struct static_call_site *site, *stop;

	cpus_read_lock();
	static_call_lock();

	if (key->func == func)
		goto done;

	key->func = func;

	/*
	 * If called before init, leave the call sites unpatched for now.
	 * In the meantime they'll continue to call the temporary trampoline.
	 */
	if (!static_call_initialized)
		goto done;

	list_for_each_entry(mod, &key->site_mods, list) {
		if (!mod->sites) {
			/*
			 * This can happen if the static call key is defined in
			 * a module which doesn't use it.
			 */
			continue;
		}

		stop = __stop_static_call_sites;

#ifdef CONFIG_MODULES
		if (mod->mod) {
			stop = mod->mod->static_call_sites +
			       mod->mod->num_static_call_sites;
		}
#endif

		for (site = mod->sites;
		     site < stop && static_call_key(site) == key; site++) {
			unsigned long addr = static_call_addr(site);

			if (!mod->mod && init_section_contains((void *)addr, 1))
				continue;
			if (mod->mod && within_module_init(addr, mod->mod))
				continue;

			arch_static_call_transform(addr, func);
		}
	}

done:
	static_call_unlock();
	cpus_read_unlock();
}
EXPORT_SYMBOL_GPL(__static_call_update);

#ifdef CONFIG_MODULES

static int static_call_add_module(struct module *mod)
{
	struct static_call_site *start = mod->static_call_sites;
	struct static_call_site *stop = mod->static_call_sites +
					mod->num_static_call_sites;
	struct static_call_site *site;
	struct static_call_key *key, *prev_key = NULL;
	struct static_call_mod *static_call_mod;

	if (start == stop)
		return 0;

	module_disable_ro(mod);
	static_call_sort_entries(start, stop);
	module_enable_ro(mod, false);

	for (site = start; site < stop; site++) {
		unsigned long addr = static_call_addr(site);

		if (within_module_init(addr, mod))
			continue;

		key = static_call_key(site);
		if (key != prev_key) {
			prev_key = key;

			static_call_mod = kzalloc(sizeof(*static_call_mod), GFP_KERNEL);
			if (!static_call_mod)
				return -ENOMEM;

			static_call_mod->mod = mod;
			static_call_mod->sites = site;
			list_add_tail(&static_call_mod->list, &key->site_mods);

			if (is_module_address((unsigned long)key)) {
				/*
				 * The trampoline should no longer be used.
				 * Poison it it with a BUG() to catch any stray
				 * callers.
				 */
				arch_static_call_poison_tramp(addr);
			}
		}

		arch_static_call_transform(addr, key->func);
	}

	return 0;
}

static void static_call_del_module(struct module *mod)
{
	struct static_call_site *start = mod->static_call_sites;
	struct static_call_site *stop = mod->static_call_sites +
					mod->num_static_call_sites;
	struct static_call_site *site;
	struct static_call_key *key, *prev_key = NULL;
	struct static_call_mod *static_call_mod;

	for (site = start; site < stop; site++) {
		key = static_call_key(site);
		if (key == prev_key)
			continue;
		prev_key = key;

		list_for_each_entry(static_call_mod, &key->site_mods, list) {
			if (static_call_mod->mod == mod) {
				list_del(&static_call_mod->list);
				kfree(static_call_mod);
				break;
			}
		}
	}
}

static int static_call_module_notify(struct notifier_block *nb,
				     unsigned long val, void *data)
{
	struct module *mod = data;
	int ret = 0;

	cpus_read_lock();
	static_call_lock();

	switch (val) {
	case MODULE_STATE_COMING:
		ret = static_call_add_module(mod);
		if (ret) {
			WARN(1, "Failed to allocate memory for static calls");
			static_call_del_module(mod);
		}
		break;
	case MODULE_STATE_GOING:
		static_call_del_module(mod);
		break;
	}

	static_call_unlock();
	cpus_read_unlock();

	return notifier_from_errno(ret);
}

static struct notifier_block static_call_module_nb = {
	.notifier_call = static_call_module_notify,
};

#endif /* CONFIG_MODULES */

static void __init static_call_init(void)
{
	struct static_call_site *start = __start_static_call_sites;
	struct static_call_site *stop  = __stop_static_call_sites;
	struct static_call_site *site;

	if (start == stop) {
		pr_warn("WARNING: empty static call table\n");
		return;
	}

	cpus_read_lock();
	static_call_lock();

	static_call_sort_entries(start, stop);

	for (site = start; site < stop; site++) {
		struct static_call_key *key = static_call_key(site);
		unsigned long addr = static_call_addr(site);

		if (list_empty(&key->site_mods)) {
			struct static_call_mod *mod;

			mod = kzalloc(sizeof(*mod), GFP_KERNEL);
			if (!mod) {
				WARN(1, "Failed to allocate memory for static calls");
				return;
			}

			mod->sites = site;
			list_add_tail(&mod->list, &key->site_mods);

			/*
			 * The trampoline should no longer be used.  Poison it
			 * it with a BUG() to catch any stray callers.
			 */
			arch_static_call_poison_tramp(addr);
		}

		arch_static_call_transform(addr, key->func);
	}

	static_call_initialized = true;

	static_call_unlock();
	cpus_read_unlock();

#ifdef CONFIG_MODULES
	register_module_notifier(&static_call_module_nb);
#endif
}
early_initcall(static_call_init);
