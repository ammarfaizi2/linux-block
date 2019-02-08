/* Container intercept interface
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/container.h>
#include <keys/request_key_auth-type.h>
#include "internal.h"

struct request_key_intercept {
	char			type[32];	/* The type of key to be trapped */
	struct list_head	link;		/* Link in containers->req_key_traps */
	struct key		*dest_keyring;	/* Where to place the trapped auth keys */
	struct ns_common	*ns;		/* Namespace the key must match */
};

/*
 * Add an intercept filter to a container.
 */
static long key_add_intercept(struct container *c, struct request_key_intercept *rki)
{
	struct request_key_intercept *p;

	kenter("%p,{%s,%d}", c, rki->type, key_serial(rki->dest_keyring));

	spin_lock(&c->lock);
	list_for_each_entry(p, &c->req_key_traps, link) {
		if (strcmp(rki->type, p->type) == 0) {
			spin_unlock(&c->lock);
			return -EEXIST;
		}
	}

	/* We put all-matching rules at the back so they're checked after the
	 * more specific rules.
	 */
	if (rki->type[0] == '*' && !rki->type[1])
		list_add_tail(&rki->link, &c->req_key_traps);
	else
		list_add(&rki->link, &c->req_key_traps);

	spin_unlock(&c->lock);
	kleave(" = 0");
	return 0;
}

/*
 * Remove one or more intercept filters from a container.  Returns the number
 * of entries removed.
 */
long key_del_intercept(struct container *c, const char *type)
{
	struct request_key_intercept *p, *q;
	long count;
	LIST_HEAD(graveyard);

	kenter("%p,%s", c, type);

	spin_lock(&c->lock);
	list_for_each_entry_safe(p, q, &c->req_key_traps, link) {
		if (!type || strcmp(p->type, type) == 0) {
			kdebug("- match %d", key_serial(p->dest_keyring));
			list_move(&p->link, &graveyard);
		}
	}
	spin_unlock(&c->lock);

	count = 0;
	while (!list_empty(&graveyard)) {
		p = list_entry(graveyard.next, struct request_key_intercept, link);
		list_del(&p->link);
		count++;

		key_put(p->dest_keyring);
		kfree(p);
	}

	kleave(" = %ld", count);
	return count;
}

/*
 * Create an intercept filter and add it to a container.
 */
static long key_create_intercept(struct container *c, const char *type,
				 key_serial_t dest_ring_id)
{
	struct request_key_intercept *rki;
	key_ref_t dest_ref;
	long ret = -ENOMEM;

	dest_ref = lookup_user_key(dest_ring_id, KEY_LOOKUP_CREATE,
				   KEY_NEED_WRITE);
	if (IS_ERR(dest_ref))
		return PTR_ERR(dest_ref);

	rki = kzalloc(sizeof(*rki), GFP_KERNEL);
	if (!rki)
		goto out_dest;

	memcpy(rki->type, type, sizeof(rki->type));
	rki->dest_keyring = key_ref_to_ptr(dest_ref);
	/* TODO: set rki->ns */

	ret = key_add_intercept(c, rki);
	if (ret < 0)
		goto out_rki;
	return ret;

out_rki:
 	kfree(rki);
out_dest:
	key_ref_put(dest_ref);
	return ret;
}

/*
 * Add or remove (if dest_keyring==0) a request_key upcall intercept trap upon
 * a container.  If _type points to a string of "*" that matches all types.
 */
long keyctl_container_intercept(int containerfd,
				const char *_type,
				unsigned int ns_id,
				key_serial_t dest_ring_id)
{
	struct container *c;
	struct fd f;
	char type[32] = "";
	long ret;

	if (containerfd < 0 || ns_id < 0)
		return -EINVAL;
	if (dest_ring_id && !_type)
		return -EINVAL;

	f = fdget(containerfd);
	if (!f.file)
		return -EBADF;
	ret = -EINVAL;
	if (!is_container_file(f.file))
		goto out_fd;

	c = f.file->private_data;

	/* Find out what type we're dealing with (can be NULL to make removal
	 * remove everything).
	 */
	if (_type) {
		ret = key_get_type_from_user(type, _type, sizeof(type));
		if (ret < 0)
			goto out_fd;
	}

	/* TODO: Get the namespace to filter on */

	/* We add a filter if a destination keyring has been specified. */
	if (dest_ring_id) {
		ret = key_create_intercept(c, type, dest_ring_id);
	} else {
		ret = key_del_intercept(c, _type ? type : NULL);
	}

out_fd:
	fdput(f);
	return ret;
}

/*
 * Queue a construction record if we can find a handler.
 *
 * Returns true if we found a handler - in which case ownership of the
 * construction record has been passed on to the service queue and the caller
 * can no longer touch it.
 */
int queue_request_key(struct key *authkey)
{
	struct container *c = current->container;
	struct request_key_intercept *rki;
	struct request_key_auth *rka = get_request_key_auth(authkey);
	struct key *service_keyring;
	struct key *key = rka->target_key;
	int ret;

	kenter("%p,%d,%d", c, key_serial(authkey), key_serial(key));

	if (list_empty(&c->req_key_traps)) {
		kleave(" = -EAGAIN [e]");
		return -EAGAIN;
	}

	spin_lock(&c->lock);

	list_for_each_entry(rki, &c->req_key_traps, link) {
		if (strcmp(rki->type, "*") == 0 ||
		    strcmp(rki->type, key->type->name) == 0)
			goto found_match;
	}

	spin_unlock(&c->lock);
	kleave(" = -EAGAIN [n]");
	return -EAGAIN;

found_match:
	service_keyring = key_get(rki->dest_keyring);
	kdebug("- match %d", key_serial(service_keyring));
	spin_unlock(&c->lock);

	/* We add the authentication key to the keyring for the service daemon
	 * to collect.  This can be detected by means of a watch on the service
	 * keyring.
	 */
	ret = key_link(service_keyring, authkey);
	key_put(service_keyring);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Query information about a request_key_auth key.
 */
long keyctl_query_request_key_auth(key_serial_t auth_id,
				   struct keyctl_query_request_key_auth __user *_data)
{
	struct keyctl_query_request_key_auth data;
	struct request_key_auth *rka;
	struct key *session;
	key_ref_t authkey_ref;

	if (auth_id <= 0 || !_data)
		return -EINVAL;

	authkey_ref = lookup_user_key(auth_id, 0, KEY_NEED_SEARCH);
	if (IS_ERR(authkey_ref))
		return PTR_ERR(authkey_ref);
	rka = get_request_key_auth(key_ref_to_ptr(authkey_ref));

	memset(&data, 0, sizeof(data));
	strlcpy(data.operation, rka->op, sizeof(data.operation));
	data.fsuid = from_kuid(current_user_ns(), rka->cred->fsuid);
	data.fsgid = from_kgid(current_user_ns(), rka->cred->fsgid);
	data.target_key = rka->target_key->serial;
	data.thread_keyring = key_serial(rka->cred->thread_keyring);
	data.process_keyring = key_serial(rka->cred->thread_keyring);

	rcu_read_lock();
	session = rcu_dereference(rka->cred->session_keyring);
	if (!session)
		session = rka->cred->user->session_keyring;
	data.session_keyring = key_serial(session);
	rcu_read_unlock();

	key_ref_put(authkey_ref);

	if (copy_to_user(_data, &data, sizeof(data)))
		return -EFAULT;

	return 0;
}

struct key_lru_search_state {
	struct key	*candidate;
	time64_t	oldest;
};

/*
 * Iterate over all the keys in the keyring looking for the one with the oldest
 * timestamp.
 */
static bool cmp_lru(const struct key *key,
			   const struct key_match_data *match_data)
{
	struct key_lru_search_state *state = (void *)match_data->raw_data;
	time64_t t;

	t = READ_ONCE(key->last_used_at);
	if (state->oldest > t && !test_bit(KEY_FLAG_SEEN, &key->flags)) {
		state->oldest = t;
		state->candidate = (struct key *)key;
	}

	return false;
}

/*
 * Find the oldest key in a keyring of a particular type.
 */
long keyctl_find_lru(key_serial_t _keyring, const char __user *type_name)
{
	struct key_lru_search_state state;
	struct keyring_search_context ctx = {
		.index_key.description	= NULL,
		.cred			= current_cred(),
		.match_data.cmp		= cmp_lru,
		.match_data.raw_data	= &state,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_ITERATE,
		.flags			= KEYRING_SEARCH_DO_STATE_CHECK,
	};
	struct key_type *ktype;
	struct key *key;
	key_ref_t keyring_ref, ref;
	char type[32];
	int ret, max_iter = 10;

	if (!_keyring || !type_name)
		return -EINVAL;

	/* We want to allow special types, such as ".request_key_auth" */
	ret = strncpy_from_user(type, type_name, sizeof(type));
	if (ret < 0)
		return ret;
	if (ret == 0 || ret >= sizeof(type))
		return -EINVAL;
	type[ret] = '\0';

	keyring_ref = lookup_user_key(_keyring, 0, KEY_NEED_SEARCH);
	if (IS_ERR(keyring_ref))
		return PTR_ERR(keyring_ref);

	if (strcmp(type, key_type_request_key_auth.name) == 0) {
		ktype = &key_type_request_key_auth;
	} else {
		ktype = key_type_lookup(type);
		if (IS_ERR(ktype)) {
			ret = PTR_ERR(ktype);
			goto error_ring;
		}
	}

	ctx.index_key.type = ktype;

	do {
		state.oldest = TIME64_MAX;
		state.candidate = NULL;

		rcu_read_lock();

		/* Scan the keyring.  We expect this to end in -EAGAIN as we
		 * can't generate a result until the entire scan is completed.
		 */
		ret = -EAGAIN;
		ref = keyring_search_aux(keyring_ref, &ctx);

		key = state.candidate;
		if (key &&
		    !test_and_set_bit(KEY_FLAG_SEEN, &key->flags) &&
		    key_validate(key) == 0) {
			ret = key->serial;
			goto error_unlock;
		}


		rcu_read_unlock();
	} while (--max_iter > 0);
	goto error_type;

error_unlock:
	rcu_read_unlock();
error_type:
	if (ktype != &key_type_request_key_auth)
		key_type_put(ktype);
error_ring:
	key_ref_put(keyring_ref);
	return ret;
}

/*
 * Attach a keyring to a container as the container key, to be searched by
 * request_key() after thread, process and session keyrings.  This is only
 * permitted once per container.
 */
long keyctl_set_container_keyring(int containerfd, key_serial_t _keyring)
{
	struct container *c;
	struct fd f;
	key_ref_t keyring_ref = NULL;
	long ret;

	if (containerfd < 0 || _keyring <= 0)
		return -EINVAL;

	f = fdget(containerfd);
	if (!f.file)
		return -EBADF;
	ret = -EINVAL;
	if (!is_container_file(f.file))
		goto out_fd;

	c = f.file->private_data;

	keyring_ref = lookup_user_key(_keyring, 0, KEY_NEED_SEARCH);
	if (IS_ERR(keyring_ref)) {
		ret = PTR_ERR(keyring_ref);
		goto out_fd;
	}

	ret = -EBUSY;
	spin_lock(&c->lock);
	if (!c->keyring) {
		c->keyring = key_get(key_ref_to_ptr(keyring_ref));
		ret = 0;
	}
	spin_unlock(&c->lock);

	key_ref_put(keyring_ref);
out_fd:
	fdput(f);
	return ret;
}
