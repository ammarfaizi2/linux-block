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


struct tpm_even_nonce {
	unsigned char data[TPM_NONCE_SIZE];
};

struct tpm_odd_nonce {
	unsigned char data[TPM_NONCE_SIZE];
};

struct tpm_osapsess {
	uint32_t handle;
	unsigned char secret[SHA1_DIGEST_SIZE];
	struct tpm_even_nonce enonce;
};

static inline void SET_BUF_OFFSET(struct tpm_buf *buffer, unsigned offset)
{
	buffer->offset = offset;
}

static inline uint16_t LOAD16(struct tpm_buf *buffer)
{
	__be16 *p = (__be16 *)(buffer->data + buffer->offset);
	buffer->offset += 2;
	return be16_to_cpup(p);
}

static inline __be32 LOAD32BE(struct tpm_buf *buffer)
{
	__be32 val = *(__be32 *)(buffer->data + buffer->offset);
	buffer->offset += 4;
	return val;
}

static inline uint32_t LOAD32(struct tpm_buf *buffer)
{
	__be32 *p = (__be32 *)(buffer->data + buffer->offset);
	buffer->offset += 4;
	return be32_to_cpup(p);
}

static inline void LOAD_S(struct tpm_buf *buffer, void *data_buffer, size_t amount)
{
	memcpy(data_buffer, buffer->data + buffer->offset, amount);
	buffer->offset += amount;
}

static inline void store_8(struct tpm_buf *buf, unsigned char value)
{
	buf->data[buf->len++] = value;
}

static inline void store16(struct tpm_buf *buf, uint16_t value)
{
	*(__be16 *)&buf->data[buf->len] = cpu_to_be16(value);
	buf->len += sizeof(value);
}

static inline void store32(struct tpm_buf *buf, uint32_t value)
{
	*(__be32 *)&buf->data[buf->len] = cpu_to_be32(value);
	buf->len += sizeof(value);
}

static inline void store_s(struct tpm_buf *buf, const void *in, int len)
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

static inline void dump_tpm_buf(struct tpm_buf *tb)
{
	int len;

	pr_info("\ntpm buffer\n");
	SET_BUF_OFFSET(tb, TPM_SIZE_OFFSET);
	len = LOAD32(tb);
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1, tb->data, len, 0);
}

#else
static inline void dump_sess(struct tpm_osapsess *s)
{
}

static inline void dump_tpm_buf(unsigned char *buf)
{
}
#endif
