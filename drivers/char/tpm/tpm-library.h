/* TPM call wrapper library internal definitions.
 *
 * Copyright (C) 2010 IBM Corporation
 *
 * Author:
 * David Safford <safford@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */


#define LOAD32(buffer, offset)	(ntohl(*(uint32_t *)&buffer[offset]))
#define LOAD32N(buffer, offset)	(*(uint32_t *)&buffer[offset])
#define LOAD16(buffer, offset)	(ntohs(*(uint16_t *)&buffer[offset]))

struct tpm_osapsess {
	uint32_t handle;
	unsigned char secret[SHA1_DIGEST_SIZE];
	unsigned char enonce[TPM_NONCE_SIZE];
};

static inline void store8(struct tpm_buf *buf, const unsigned char value)
{
	buf->data[buf->len++] = value;
}

static inline void store16(struct tpm_buf *buf, const uint16_t value)
{
	*(uint16_t *) & buf->data[buf->len] = htons(value);
	buf->len += sizeof value;
}

static inline void store32(struct tpm_buf *buf, const uint32_t value)
{
	*(uint32_t *) & buf->data[buf->len] = htonl(value);
	buf->len += sizeof value;
}

static inline void storebytes(struct tpm_buf *buf, const unsigned char *in,
			      const int len)
{
	memcpy(buf->data + buf->len, in, len);
	buf->len += len;
}

/*
 * Debugging
 */
#define TPM_DEBUG 0

#ifdef TPM_DEBUG
static inline void dump_sess(struct tpm_osapsess *s)
{
	print_hex_dump(KERN_INFO, "handle ", DUMP_PREFIX_NONE,
		       16, 1, &s->handle, 4, 0);
	pr_info("secret:\n");
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE,
		       16, 1, &s->secret, SHA1_DIGEST_SIZE, 0);
	pr_info("enonce:\n");
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE,
		       16, 1, &s->enonce, SHA1_DIGEST_SIZE, 0);
}

static inline void dump_tpm_buf(unsigned char *buf)
{
	int len;

	pr_info("\ntpm buffer\n");
	len = LOAD32(buf, TPM_SIZE_OFFSET);
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1, buf, len, 0);
}

#else
static inline void dump_sess(struct tpm_osapsess *s)
{
}

static inline void dump_tpm_buf(unsigned char *buf)
{
}
#endif
