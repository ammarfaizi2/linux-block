/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_ETHERDEVICE_API_ADDR_H
#define _LINUX_ETHERDEVICE_API_ADDR_H

#include <linux/etherdevice_types.h>

#include <linux/string.h>

struct device;
struct net_device;

struct fwnode_handle;

int eth_platform_get_mac_address(struct device *dev, u8 *mac_addr);
int platform_get_ethdev_address(struct device *dev, struct net_device *netdev);
unsigned char *arch_get_platform_mac_address(void);
int nvmem_get_mac_address(struct device *dev, void *addrbuf);
int device_get_mac_address(struct device *dev, char *addr);
int device_get_ethdev_address(struct device *dev, struct net_device *netdev);
int fwnode_get_mac_address(struct fwnode_handle *fwnode, char *addr);

int eth_prepare_mac_addr_change(struct net_device *dev, void *p);
void eth_commit_mac_addr_change(struct net_device *dev, void *p);
int eth_mac_addr(struct net_device *dev, void *p);
int eth_validate_addr(struct net_device *dev);

/* Reserved Ethernet Addresses per IEEE 802.1Q */
static const u8 eth_reserved_addr_base[ETH_ALEN] __aligned(2) =
{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };
#define eth_stp_addr eth_reserved_addr_base

/**
 * is_link_local_ether_addr - Determine if given Ethernet address is link-local
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if address is link local reserved addr (01:80:c2:00:00:0X) per
 * IEEE 802.1Q 8.6.3 Frame filtering.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_link_local_ether_addr(const u8 *addr)
{
	__be16 *a = (__be16 *)addr;
	static const __be16 *b = (const __be16 *)eth_reserved_addr_base;
	static const __be16 m = cpu_to_be16(0xfff0);

#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	return (((*(const u32 *)addr) ^ (*(const u32 *)b)) |
		(__force int)((a[2] ^ b[2]) & m)) == 0;
#else
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
#endif
}

/**
 * is_zero_ether_addr - Determine if give Ethernet address is all zeros.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is all zeroes.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_zero_ether_addr(const u8 *addr)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	return ((*(const u32 *)addr) | (*(const u16 *)(addr + 4))) == 0;
#else
	return (*(const u16 *)(addr + 0) |
		*(const u16 *)(addr + 2) |
		*(const u16 *)(addr + 4)) == 0;
#endif
}

/**
 * is_multicast_ether_addr - Determine if the Ethernet address is a multicast.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a multicast address.
 * By definition the broadcast address is also a multicast address.
 */
static inline bool is_multicast_ether_addr(const u8 *addr)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	u32 a = *(const u32 *)addr;
#else
	u16 a = *(const u16 *)addr;
#endif
#ifdef __BIG_ENDIAN
	return 0x01 & (a >> ((sizeof(a) * 8) - 8));
#else
	return 0x01 & a;
#endif
}

static inline bool is_multicast_ether_addr_64bits(const u8 addr[6+2])
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
#ifdef __BIG_ENDIAN
	return 0x01 & ((*(const u64 *)addr) >> 56);
#else
	return 0x01 & (*(const u64 *)addr);
#endif
#else
	return is_multicast_ether_addr(addr);
#endif
}

/**
 * is_local_ether_addr - Determine if the Ethernet address is locally-assigned one (IEEE 802).
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a local address.
 */
static inline bool is_local_ether_addr(const u8 *addr)
{
	return 0x02 & addr[0];
}

/**
 * is_broadcast_ether_addr - Determine if the Ethernet address is broadcast
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is the broadcast address.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_broadcast_ether_addr(const u8 *addr)
{
	return (*(const u16 *)(addr + 0) &
		*(const u16 *)(addr + 2) &
		*(const u16 *)(addr + 4)) == 0xffff;
}

/**
 * is_unicast_ether_addr - Determine if the Ethernet address is unicast
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a unicast address.
 */
static inline bool is_unicast_ether_addr(const u8 *addr)
{
	return !is_multicast_ether_addr(addr);
}

/**
 * is_valid_ether_addr - Determine if the given Ethernet address is valid
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Check that the Ethernet address (MAC) is not 00:00:00:00:00:00, is not
 * a multicast address, and is not FF:FF:FF:FF:FF:FF.
 *
 * Return true if the address is valid.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_valid_ether_addr(const u8 *addr)
{
	/* FF:FF:FF:FF:FF:FF is a multicast address so we don't need to
	 * explicitly check for it here. */
	return !is_multicast_ether_addr(addr) && !is_zero_ether_addr(addr);
}

/**
 * eth_broadcast_addr - Assign broadcast address
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Assign the broadcast address to the given address array.
 */
static inline void eth_broadcast_addr(u8 *addr)
{
	memset(addr, 0xff, ETH_ALEN);
}

/**
 * eth_zero_addr - Assign zero address
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Assign the zero address to the given address array.
 */
static inline void eth_zero_addr(u8 *addr)
{
	memset(addr, 0x00, ETH_ALEN);
}

/**
 * ether_addr_copy - Copy an Ethernet address
 * @dst: Pointer to a six-byte array Ethernet address destination
 * @src: Pointer to a six-byte array Ethernet address source
 *
 * Please note: dst & src must both be aligned to u16.
 */
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}

/**
 * ether_addr_equal - Compare two Ethernet addresses
 * @addr1: Pointer to a six-byte array containing the Ethernet address
 * @addr2: Pointer other six-byte array containing the Ethernet address
 *
 * Compare two Ethernet addresses, returns true if equal
 *
 * Please note: addr1 & addr2 must both be aligned to u16.
 */
static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	u32 fold = ((*(const u32 *)addr1) ^ (*(const u32 *)addr2)) |
		   ((*(const u16 *)(addr1 + 4)) ^ (*(const u16 *)(addr2 + 4)));

	return fold == 0;
#else
	const u16 *a = (const u16 *)addr1;
	const u16 *b = (const u16 *)addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0;
#endif
}

/**
 * ether_addr_equal_64bits - Compare two Ethernet addresses
 * @addr1: Pointer to an array of 8 bytes
 * @addr2: Pointer to an other array of 8 bytes
 *
 * Compare two Ethernet addresses, returns true if equal, false otherwise.
 *
 * The function doesn't need any conditional branches and possibly uses
 * word memory accesses on CPU allowing cheap unaligned memory reads.
 * arrays = { byte1, byte2, byte3, byte4, byte5, byte6, pad1, pad2 }
 *
 * Please note that alignment of addr1 & addr2 are only guaranteed to be 16 bits.
 */

static inline bool ether_addr_equal_64bits(const u8 addr1[6+2],
					   const u8 addr2[6+2])
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	u64 fold = (*(const u64 *)addr1) ^ (*(const u64 *)addr2);

#ifdef __BIG_ENDIAN
	return (fold >> 16) == 0;
#else
	return (fold << 16) == 0;
#endif
#else
	return ether_addr_equal(addr1, addr2);
#endif
}

/**
 * ether_addr_equal_unaligned - Compare two not u16 aligned Ethernet addresses
 * @addr1: Pointer to a six-byte array containing the Ethernet address
 * @addr2: Pointer other six-byte array containing the Ethernet address
 *
 * Compare two Ethernet addresses, returns true if equal
 *
 * Please note: Use only when any Ethernet address may not be u16 aligned.
 */
static inline bool ether_addr_equal_unaligned(const u8 *addr1, const u8 *addr2)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	return ether_addr_equal(addr1, addr2);
#else
	return memcmp(addr1, addr2, ETH_ALEN) == 0;
#endif
}

/**
 * ether_addr_equal_masked - Compare two Ethernet addresses with a mask
 * @addr1: Pointer to a six-byte array containing the 1st Ethernet address
 * @addr2: Pointer to a six-byte array containing the 2nd Ethernet address
 * @mask: Pointer to a six-byte array containing the Ethernet address bitmask
 *
 * Compare two Ethernet addresses with a mask, returns true if for every bit
 * set in the bitmask the equivalent bits in the ethernet addresses are equal.
 * Using a mask with all bits set is a slower ether_addr_equal.
 */
static inline bool ether_addr_equal_masked(const u8 *addr1, const u8 *addr2,
					   const u8 *mask)
{
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		if ((addr1[i] ^ addr2[i]) & mask[i])
			return false;
	}

	return true;
}

/**
 * ether_addr_to_u64 - Convert an Ethernet address into a u64 value.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return a u64 value of the address
 */
static inline u64 ether_addr_to_u64(const u8 *addr)
{
	u64 u = 0;
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		u = u << 8 | addr[i];

	return u;
}

/**
 * u64_to_ether_addr - Convert a u64 to an Ethernet address.
 * @u: u64 to convert to an Ethernet MAC address
 * @addr: Pointer to a six-byte array to contain the Ethernet address
 */
static inline void u64_to_ether_addr(u64 u, u8 *addr)
{
	int i;

	for (i = ETH_ALEN - 1; i >= 0; i--) {
		addr[i] = u & 0xff;
		u = u >> 8;
	}
}

/**
 * eth_addr_dec - Decrement the given MAC address
 *
 * @addr: Pointer to a six-byte array containing Ethernet address to decrement
 */
static inline void eth_addr_dec(u8 *addr)
{
	u64 u = ether_addr_to_u64(addr);

	u--;
	u64_to_ether_addr(u, addr);
}

/**
 * eth_addr_inc() - Increment the given MAC address.
 * @addr: Pointer to a six-byte array containing Ethernet address to increment.
 */
static inline void eth_addr_inc(u8 *addr)
{
	u64 u = ether_addr_to_u64(addr);

	u++;
	u64_to_ether_addr(u, addr);
}

/**
 * eth_proto_is_802_3 - Determine if a given Ethertype/length is a protocol
 * @proto: Ethertype/length value to be tested
 *
 * Check that the value from the Ethertype/length field is a valid Ethertype.
 *
 * Return true if the valid is an 802.3 supported Ethertype.
 */
static inline bool eth_proto_is_802_3(__be16 proto)
{
#ifndef __BIG_ENDIAN
	/* if CPU is little endian mask off bits representing LSB */
	proto &= htons(0xFF00);
#endif
	/* cast both to u16 and compare since LSB can be ignored */
	return (__force u16)proto >= (__force u16)htons(ETH_P_802_3_MIN);
}

#endif  /* _LINUX_ETHERDEVICE_API_ADDR_H */
