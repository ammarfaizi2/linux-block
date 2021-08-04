/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  NET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Ethernet handlers.
 *
 * Version:	@(#)eth.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		Relocated to include/linux where it belongs by Alan Cox
 *							<gw4pts@gw4pts.ampr.org>
 */
#ifndef _LINUX_ETHERDEVICE_API_H
#define _LINUX_ETHERDEVICE_API_H

#include <linux/etherdevice_types.h>
#include <linux/etherdevice_api_addr.h>

#include <linux/skbuff_api.h>
#include <linux/if_ether.h>
#include <linux/netdevice_api.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <asm/unaligned.h>
#include <asm/bitsperlong.h>

#ifdef __KERNEL__
struct device;
u32 eth_get_headlen(const struct net_device *dev, const void *data, u32 len);
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);
extern const struct header_ops eth_header_ops;

int eth_header(struct sk_buff *skb, struct net_device *dev, unsigned short type,
	       const void *daddr, const void *saddr, unsigned len);
int eth_header_parse(const struct sk_buff *skb, unsigned char *haddr);
int eth_header_cache(const struct neighbour *neigh, struct hh_cache *hh,
		     __be16 type);
void eth_header_cache_update(struct hh_cache *hh, const struct net_device *dev,
			     const unsigned char *haddr);
__be16 eth_header_parse_protocol(const struct sk_buff *skb);

struct net_device *alloc_etherdev_mqs(int sizeof_priv, unsigned int txqs,
					    unsigned int rxqs);
#define alloc_etherdev(sizeof_priv) alloc_etherdev_mq(sizeof_priv, 1)
#define alloc_etherdev_mq(sizeof_priv, count) alloc_etherdev_mqs(sizeof_priv, count, count)

struct net_device *devm_alloc_etherdev_mqs(struct device *dev, int sizeof_priv,
					   unsigned int txqs,
					   unsigned int rxqs);
#define devm_alloc_etherdev(dev, sizeof_priv) devm_alloc_etherdev_mqs(dev, sizeof_priv, 1, 1)

struct sk_buff *eth_gro_receive(struct list_head *head, struct sk_buff *skb);
int eth_gro_complete(struct sk_buff *skb, int nhoff);

/**
 * eth_random_addr - Generate software assigned random Ethernet address
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Generate a random Ethernet address (MAC) that is not multicast
 * and has the local assigned bit set.
 */
static inline void eth_random_addr(u8 *addr)
{
	get_random_bytes(addr, ETH_ALEN);
	addr[0] &= 0xfe;	/* clear multicast bit */
	addr[0] |= 0x02;	/* set local assignment bit (IEEE802) */
}

/**
 * eth_hw_addr_random - Generate software assigned random Ethernet and
 * set device flag
 * @dev: pointer to net_device structure
 *
 * Generate a random Ethernet address (MAC) to be used by a net device
 * and set addr_assign_type so the state can be read by sysfs and be
 * used by userspace.
 */
static inline void eth_hw_addr_random(struct net_device *dev)
{
	u8 addr[ETH_ALEN];

	eth_random_addr(addr);
	__dev_addr_set(dev, addr, ETH_ALEN);
	dev->addr_assign_type = NET_ADDR_RANDOM;
}

/**
 * eth_hw_addr_crc - Calculate CRC from netdev_hw_addr
 * @ha: pointer to hardware address
 *
 * Calculate CRC from a hardware address as basis for filter hashes.
 */
static inline u32 eth_hw_addr_crc(struct netdev_hw_addr *ha)
{
	return ether_crc(ETH_ALEN, ha->addr);
}

/**
 * eth_hw_addr_set - Assign Ethernet address to a net_device
 * @dev: pointer to net_device structure
 * @addr: address to assign
 *
 * Assign given address to the net_device, addr_assign_type is not changed.
 */
static inline void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
	__dev_addr_set(dev, addr, ETH_ALEN);
}

/**
 * eth_hw_addr_inherit - Copy dev_addr from another net_device
 * @dst: pointer to net_device to copy dev_addr to
 * @src: pointer to net_device to copy dev_addr from
 *
 * Copy the Ethernet address from one net_device to another along with
 * the address attributes (addr_assign_type).
 */
static inline void eth_hw_addr_inherit(struct net_device *dst,
				       struct net_device *src)
{
	dst->addr_assign_type = src->addr_assign_type;
	eth_hw_addr_set(dst, src->dev_addr);
}

#endif	/* __KERNEL__ */

/**
 * compare_ether_header - Compare two Ethernet headers
 * @a: Pointer to Ethernet header
 * @b: Pointer to Ethernet header
 *
 * Compare two Ethernet headers, returns 0 if equal.
 * This assumes that the network header (i.e., IP header) is 4-byte
 * aligned OR the platform can handle unaligned access.  This is the
 * case for all packets coming into netif_receive_skb or similar
 * entry points.
 */

static inline unsigned long compare_ether_header(const void *a, const void *b)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	unsigned long fold;

	/*
	 * We want to compare 14 bytes:
	 *  [a0 ... a13] ^ [b0 ... b13]
	 * Use two long XOR, ORed together, with an overlap of two bytes.
	 *  [a0  a1  a2  a3  a4  a5  a6  a7 ] ^ [b0  b1  b2  b3  b4  b5  b6  b7 ] |
	 *  [a6  a7  a8  a9  a10 a11 a12 a13] ^ [b6  b7  b8  b9  b10 b11 b12 b13]
	 * This means the [a6 a7] ^ [b6 b7] part is done two times.
	*/
	fold = *(unsigned long *)a ^ *(unsigned long *)b;
	fold |= *(unsigned long *)(a + 6) ^ *(unsigned long *)(b + 6);
	return fold;
#else
	u32 *a32 = (u32 *)((u8 *)a + 2);
	u32 *b32 = (u32 *)((u8 *)b + 2);

	return (*(u16 *)a ^ *(u16 *)b) | (a32[0] ^ b32[0]) |
	       (a32[1] ^ b32[1]) | (a32[2] ^ b32[2]);
#endif
}

/**
 * eth_hw_addr_gen - Generate and assign Ethernet address to a port
 * @dev: pointer to port's net_device structure
 * @base_addr: base Ethernet address
 * @id: offset to add to the base address
 *
 * Generate a MAC address using a base address and an offset and assign it
 * to a net_device. Commonly used by switch drivers which need to compute
 * addresses for all their ports. addr_assign_type is not changed.
 */
static inline void eth_hw_addr_gen(struct net_device *dev, const u8 *base_addr,
				   unsigned int id)
{
	u64 u = ether_addr_to_u64(base_addr);
	u8 addr[ETH_ALEN];

	u += id;
	u64_to_ether_addr(u, addr);
	eth_hw_addr_set(dev, addr);
}

/**
 * eth_skb_pad - Pad buffer to mininum number of octets for Ethernet frame
 * @skb: Buffer to pad
 *
 * An Ethernet frame should have a minimum size of 60 bytes.  This function
 * takes short frames and pads them with zeros up to the 60 byte limit.
 */
static inline int eth_skb_pad(struct sk_buff *skb)
{
	return skb_put_padto(skb, ETH_ZLEN);
}

#endif	/* _LINUX_ETHERDEVICE_API_H */
