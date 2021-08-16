/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _UDP_API_TABLE_H
#define _UDP_API_TABLE_H

#include <net/udp.h>

#include <linux/udp_api.h>

/**
 *	struct udp_table - UDP table
 *
 *	@hash:	hash table, sockets are hashed on (local port)
 *	@hash2:	hash table, sockets are hashed on (local port, local address)
 *	@mask:	number of slots in hash tables, minus 1
 *	@log:	log2(number of slots in hash table)
 */
struct udp_table {
	struct udp_hslot	*hash;
	struct udp_hslot	*hash2;
	unsigned int		mask;
	unsigned int		log;
};

extern struct udp_table udp_table;

void udp_table_init(struct udp_table *, const char *);

static inline struct udp_hslot *udp_hashslot(struct udp_table *table,
					     struct net *net, unsigned int num)
{
	return &table->hash[udp_hashfn(net, num, table->mask)];
}

/*
 * For secondary hash, net_hash_mix() is performed before calling
 * udp_hashslot2(), this explains difference with udp_hashslot()
 */
static inline struct udp_hslot *udp_hashslot2(struct udp_table *table,
					      unsigned int hash)
{
	return &table->hash2[hash & table->mask];
}

#endif	/* _UDP_API_TABLE_H */
