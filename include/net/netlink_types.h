/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_NETLINK_TYPES_H
#define __NET_NETLINK_TYPES_H

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/jiffies.h>
#include <linux/in6.h>
#include <linux/skbuff_api.h>

 /**
  * Standard attribute types to specify validation policy
  */
enum {
	NLA_UNSPEC,
	NLA_U8,
	NLA_U16,
	NLA_U32,
	NLA_U64,
	NLA_STRING,
	NLA_FLAG,
	NLA_MSECS,
	NLA_NESTED,
	NLA_NESTED_ARRAY,
	NLA_NUL_STRING,
	NLA_BINARY,
	NLA_S8,
	NLA_S16,
	NLA_S32,
	NLA_S64,
	NLA_BITFIELD32,
	NLA_REJECT,
	__NLA_TYPE_MAX,
};

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

struct netlink_range_validation {
	u64 min, max;
};

struct netlink_range_validation_signed {
	s64 min, max;
};

enum nla_policy_validation {
	NLA_VALIDATE_NONE,
	NLA_VALIDATE_RANGE,
	NLA_VALIDATE_RANGE_WARN_TOO_LONG,
	NLA_VALIDATE_MIN,
	NLA_VALIDATE_MAX,
	NLA_VALIDATE_MASK,
	NLA_VALIDATE_RANGE_PTR,
	NLA_VALIDATE_FUNCTION,
};

/**
 * struct nla_policy - attribute validation policy
 * @type: Type of attribute or NLA_UNSPEC
 * @validation_type: type of attribute validation done in addition to
 *	type-specific validation (e.g. range, function call), see
 *	&enum nla_policy_validation
 * @len: Type specific length of payload
 *
 * Policies are defined as arrays of this struct, the array must be
 * accessible by attribute type up to the highest identifier to be expected.
 *
 * Meaning of `len' field:
 *    NLA_STRING           Maximum length of string
 *    NLA_NUL_STRING       Maximum length of string (excluding NUL)
 *    NLA_FLAG             Unused
 *    NLA_BINARY           Maximum length of attribute payload
 *                         (but see also below with the validation type)
 *    NLA_NESTED,
 *    NLA_NESTED_ARRAY     Length verification is done by checking len of
 *                         nested header (or empty); len field is used if
 *                         nested_policy is also used, for the max attr
 *                         number in the nested policy.
 *    NLA_U8, NLA_U16,
 *    NLA_U32, NLA_U64,
 *    NLA_S8, NLA_S16,
 *    NLA_S32, NLA_S64,
 *    NLA_MSECS            Leaving the length field zero will verify the
 *                         given type fits, using it verifies minimum length
 *                         just like "All other"
 *    NLA_BITFIELD32       Unused
 *    NLA_REJECT           Unused
 *    All other            Minimum length of attribute payload
 *
 * Meaning of validation union:
 *    NLA_BITFIELD32       This is a 32-bit bitmap/bitselector attribute and
 *                         `bitfield32_valid' is the u32 value of valid flags
 *    NLA_REJECT           This attribute is always rejected and `reject_message'
 *                         may point to a string to report as the error instead
 *                         of the generic one in extended ACK.
 *    NLA_NESTED           `nested_policy' to a nested policy to validate, must
 *                         also set `len' to the max attribute number. Use the
 *                         provided NLA_POLICY_NESTED() macro.
 *                         Note that nla_parse() will validate, but of course not
 *                         parse, the nested sub-policies.
 *    NLA_NESTED_ARRAY     `nested_policy' points to a nested policy to validate,
 *                         must also set `len' to the max attribute number. Use
 *                         the provided NLA_POLICY_NESTED_ARRAY() macro.
 *                         The difference to NLA_NESTED is the structure:
 *                         NLA_NESTED has the nested attributes directly inside
 *                         while an array has the nested attributes at another
 *                         level down and the attribute types directly in the
 *                         nesting don't matter.
 *    NLA_U8,
 *    NLA_U16,
 *    NLA_U32,
 *    NLA_U64,
 *    NLA_S8,
 *    NLA_S16,
 *    NLA_S32,
 *    NLA_S64              The `min' and `max' fields are used depending on the
 *                         validation_type field, if that is min/max/range then
 *                         the min, max or both are used (respectively) to check
 *                         the value of the integer attribute.
 *                         Note that in the interest of code simplicity and
 *                         struct size both limits are s16, so you cannot
 *                         enforce a range that doesn't fall within the range
 *                         of s16 - do that as usual in the code instead.
 *                         Use the NLA_POLICY_MIN(), NLA_POLICY_MAX() and
 *                         NLA_POLICY_RANGE() macros.
 *    NLA_U8,
 *    NLA_U16,
 *    NLA_U32,
 *    NLA_U64              If the validation_type field instead is set to
 *                         NLA_VALIDATE_RANGE_PTR, `range' must be a pointer
 *                         to a struct netlink_range_validation that indicates
 *                         the min/max values.
 *                         Use NLA_POLICY_FULL_RANGE().
 *    NLA_S8,
 *    NLA_S16,
 *    NLA_S32,
 *    NLA_S64              If the validation_type field instead is set to
 *                         NLA_VALIDATE_RANGE_PTR, `range_signed' must be a
 *                         pointer to a struct netlink_range_validation_signed
 *                         that indicates the min/max values.
 *                         Use NLA_POLICY_FULL_RANGE_SIGNED().
 *
 *    NLA_BINARY           If the validation type is like the ones for integers
 *                         above, then the min/max length (not value like for
 *                         integers) of the attribute is enforced.
 *
 *    All other            Unused - but note that it's a union
 *
 * Meaning of `validate' field, use via NLA_POLICY_VALIDATE_FN:
 *    NLA_BINARY           Validation function called for the attribute.
 *    All other            Unused - but note that it's a union
 *
 * Example:
 *
 * static const u32 myvalidflags = 0xff231023;
 *
 * static const struct nla_policy my_policy[ATTR_MAX+1] = {
 *	[ATTR_FOO] = { .type = NLA_U16 },
 *	[ATTR_BAR] = { .type = NLA_STRING, .len = BARSIZ },
 *	[ATTR_BAZ] = NLA_POLICY_EXACT_LEN(sizeof(struct mystruct)),
 *	[ATTR_GOO] = NLA_POLICY_BITFIELD32(myvalidflags),
 * };
 */
struct nla_policy {
	u8		type;
	u8		validation_type;
	u16		len;
	union {
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		struct netlink_range_validation *range;
		struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min, max;
		};
		int (*validate)(const struct nlattr *attr,
				struct netlink_ext_ack *extack);
		/* This entry is special, and used for the attribute at index 0
		 * only, and specifies special data about the policy, namely it
		 * specifies the "boundary type" where strict length validation
		 * starts for any attribute types >= this value, also, strict
		 * nesting validation starts here.
		 *
		 * Additionally, it means that NLA_UNSPEC is actually NLA_REJECT
		 * for any types >= this, so need to use NLA_POLICY_MIN_LEN() to
		 * get the previous pure { .len = xyz } behaviour. The advantage
		 * of this is that types not specified in the policy will be
		 * rejected.
		 *
		 * For completely new families it should be set to 1 so that the
		 * validation is enforced for all attributes. For existing ones
		 * it should be set at least when new attributes are added to
		 * the enum used by the policy, and be set to the new value that
		 * was added to enforce strict validation from thereon.
		 */
		u16 strict_start_type;
	};
};

/**
 * struct nl_info - netlink source information
 * @nlh: Netlink message header of original request
 * @nl_net: Network namespace
 * @portid: Netlink PORTID of requesting application
 * @skip_notify: Skip netlink notifications to user space
 * @skip_notify_kernel: Skip selected in-kernel notifications
 */
struct nl_info {
	struct nlmsghdr		*nlh;
	struct net		*nl_net;
	u32			portid;
	u8			skip_notify:1,
				skip_notify_kernel:1;
};

#endif /* __NET_NETLINK_TYPES_H */
