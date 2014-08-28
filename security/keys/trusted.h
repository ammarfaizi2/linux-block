#ifndef __TRUSTED_KEY_H
#define __TRUSTED_KEY_H

/* discrete values, but have to store in uint16_t for TPM use */
enum {
	SEAL_keytype = 1,
	SRK_keytype = 4
};

struct trusted_key_options {
	uint16_t keytype;
	uint32_t keyhandle;
	unsigned char keyauth[SHA1_DIGEST_SIZE];
	unsigned char blobauth[SHA1_DIGEST_SIZE];
	uint32_t pcrinfo_len;
	unsigned char pcrinfo[MAX_PCRINFO_SIZE];
	int pcrlock;
};

#define TPM_DEBUG 0

#if TPM_DEBUG
static inline void dump_options(struct trusted_key_options *o)
{
	pr_info("trusted_key: sealing key type %d\n", o->keytype);
	pr_info("trusted_key: sealing key handle %0X\n", o->keyhandle);
	pr_info("trusted_key: pcrlock %d\n", o->pcrlock);
	pr_info("trusted_key: pcrinfo %d\n", o->pcrinfo_len);
	print_hex_dump(KERN_INFO, "pcrinfo ", DUMP_PREFIX_NONE,
		       16, 1, o->pcrinfo, o->pcrinfo_len, 0);
}

static inline void dump_payload(struct trusted_key_payload *p)
{
	pr_info("trusted_key: key_len %d\n", p->key_len);
	print_hex_dump(KERN_INFO, "key ", DUMP_PREFIX_NONE,
		       16, 1, p->key, p->key_len, 0);
	pr_info("trusted_key: bloblen %d\n", p->blob_len);
	print_hex_dump(KERN_INFO, "blob ", DUMP_PREFIX_NONE,
		       16, 1, p->blob, p->blob_len, 0);
	pr_info("trusted_key: migratable %d\n", p->migratable);
}

#else
static inline void dump_options(struct trusted_key_options *o)
{
}

static inline void dump_payload(struct trusted_key_payload *p)
{
}

#endif
#endif
