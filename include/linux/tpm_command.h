#ifndef __LINUX_TPM_COMMAND_H__
#define __LINUX_TPM_COMMAND_H__

/*
 * TPM Command constants from specifications at
 * http://www.trustedcomputinggroup.org
 */

/* Command TAGS */
#define TPM_TAG_RQU_COMMAND             193
#define TPM_TAG_RQU_AUTH1_COMMAND       194
#define TPM_TAG_RQU_AUTH2_COMMAND       195
#define TPM_TAG_RSP_COMMAND             196
#define TPM_TAG_RSP_AUTH1_COMMAND       197
#define TPM_TAG_RSP_AUTH2_COMMAND       198

/* Command Ordinals */
enum tpm_ordinal {
	TPM_ORD_OSAP			= 11,
	TPM_ORD_OIAP			= 10,
	TPM_ORD_PCR_EXTEND		= 20,
	TPM_ORD_PCR_READ		= 21,
	TPM_ORD_SEAL			= 23,
	TPM_ORD_UNSEAL			= 24,
	TPM_ORD_GET_RANDOM		= 70,
	TPM_ORD_CONTINUE_SELFTEST	= 83,
	TPM_ORD_GET_CAP			= 101,
	TPM_ORD_READPUBEK		= 124,
	TPM_ORD_SAVESTATE		= 152,
	TPM_ORD_STARTUP			= 153,
};

/* Other constants */
#define SRKHANDLE                       0x40000000
#define TPM_NONCE_SIZE                  20

#endif
