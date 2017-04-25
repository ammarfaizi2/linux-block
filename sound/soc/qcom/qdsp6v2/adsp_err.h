/*
 * Copyright (c) 2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __ADSP_ERR__
#define __ADSP_ERR__

#include <linux/errno.h>
//#include <sound/apr_audio-v2.h>

/* ERROR CODES */
/* Success. The operation completed with no errors. */
#define ADSP_EOK          0x00000000
/* General failure. */
#define ADSP_EFAILED      0x00000001
/* Bad operation parameter. */
#define ADSP_EBADPARAM    0x00000002
/* Unsupported routine or operation. */
#define ADSP_EUNSUPPORTED 0x00000003
/* Unsupported version. */
#define ADSP_EVERSION     0x00000004
/* Unexpected problem encountered. */
#define ADSP_EUNEXPECTED  0x00000005
/* Unhandled problem occurred. */
#define ADSP_EPANIC       0x00000006
/* Unable to allocate resource. */
#define ADSP_ENORESOURCE  0x00000007
/* Invalid handle. */
#define ADSP_EHANDLE      0x00000008
/* Operation is already processed. */
#define ADSP_EALREADY     0x00000009
/* Operation is not ready to be processed. */
#define ADSP_ENOTREADY    0x0000000A
/* Operation is pending completion. */
#define ADSP_EPENDING     0x0000000B
/* Operation could not be accepted or processed. */
#define ADSP_EBUSY        0x0000000C
/* Operation aborted due to an error. */
#define ADSP_EABORTED     0x0000000D
/* Operation preempted by a higher priority. */
#define ADSP_EPREEMPTED   0x0000000E
/* Operation requests intervention to complete. */
#define ADSP_ECONTINUE    0x0000000F
/* Operation requests immediate intervention to complete. */
#define ADSP_EIMMEDIATE   0x00000010
/* Operation is not implemented. */
#define ADSP_ENOTIMPL     0x00000011
/* Operation needs more data or resources. */
#define ADSP_ENEEDMORE    0x00000012
/* Operation does not have memory. */
#define ADSP_ENOMEMORY    0x00000014
/* Item does not exist. */
#define ADSP_ENOTEXIST    0x00000015
/* Max count for adsp error code sent to HLOS*/
#define ADSP_ERR_MAX      (ADSP_ENOTEXIST + 1)
/* Operation is finished. */
#define ADSP_ETERMINATED    0x00011174

/* ERROR STRING */
/* Success. The operation completed with no errors. */
#define ADSP_EOK_STR          "ADSP_EOK"
/* General failure. */
#define ADSP_EFAILED_STR      "ADSP_EFAILED"
/* Bad operation parameter. */
#define ADSP_EBADPARAM_STR    "ADSP_EBADPARAM"
/* Unsupported routine or operation. */
#define ADSP_EUNSUPPORTED_STR "ADSP_EUNSUPPORTED"
/* Unsupported version. */
#define ADSP_EVERSION_STR     "ADSP_EVERSION"
/* Unexpected problem encountered. */
#define ADSP_EUNEXPECTED_STR  "ADSP_EUNEXPECTED"
/* Unhandled problem occurred. */
#define ADSP_EPANIC_STR       "ADSP_EPANIC"
/* Unable to allocate resource. */
#define ADSP_ENORESOURCE_STR  "ADSP_ENORESOURCE"
/* Invalid handle. */
#define ADSP_EHANDLE_STR      "ADSP_EHANDLE"
/* Operation is already processed. */
#define ADSP_EALREADY_STR     "ADSP_EALREADY"
/* Operation is not ready to be processed. */
#define ADSP_ENOTREADY_STR    "ADSP_ENOTREADY"
/* Operation is pending completion. */
#define ADSP_EPENDING_STR     "ADSP_EPENDING"
/* Operation could not be accepted or processed. */
#define ADSP_EBUSY_STR        "ADSP_EBUSY"
/* Operation aborted due to an error. */
#define ADSP_EABORTED_STR     "ADSP_EABORTED"
/* Operation preempted by a higher priority. */
#define ADSP_EPREEMPTED_STR   "ADSP_EPREEMPTED"
/* Operation requests intervention to complete. */
#define ADSP_ECONTINUE_STR    "ADSP_ECONTINUE"
/* Operation requests immediate intervention to complete. */
#define ADSP_EIMMEDIATE_STR   "ADSP_EIMMEDIATE"
/* Operation is not implemented. */
#define ADSP_ENOTIMPL_STR     "ADSP_ENOTIMPL"
/* Operation needs more data or resources. */
#define ADSP_ENEEDMORE_STR    "ADSP_ENEEDMORE"
/* Operation does not have memory. */
#define ADSP_ENOMEMORY_STR    "ADSP_ENOMEMORY"
/* Item does not exist. */
#define ADSP_ENOTEXIST_STR    "ADSP_ENOTEXIST"
/* Unexpected error code. */
#define ADSP_ERR_MAX_STR      "ADSP_ERR_MAX"


struct adsp_err_code {
	int		lnx_err_code;
	char	*adsp_err_str;
};


static struct adsp_err_code adsp_err_code_info[ADSP_ERR_MAX+1] = {
	{ 0, ADSP_EOK_STR},
	{ -ENOTRECOVERABLE, ADSP_EFAILED_STR},
	{ -EINVAL, ADSP_EBADPARAM_STR},
	{ -ENOSYS, ADSP_EUNSUPPORTED_STR},
	{ -ENOPROTOOPT, ADSP_EVERSION_STR},
	{ -ENOTRECOVERABLE, ADSP_EUNEXPECTED_STR},
	{ -ENOTRECOVERABLE, ADSP_EPANIC_STR},
	{ -ENOSPC, ADSP_ENORESOURCE_STR},
	{ -EBADR, ADSP_EHANDLE_STR},
	{ -EALREADY, ADSP_EALREADY_STR},
	{ -EPERM, ADSP_ENOTREADY_STR},
	{ -EINPROGRESS, ADSP_EPENDING_STR},
	{ -EBUSY, ADSP_EBUSY_STR},
	{ -ECANCELED, ADSP_EABORTED_STR},
	{ -EAGAIN, ADSP_EPREEMPTED_STR},
	{ -EAGAIN, ADSP_ECONTINUE_STR},
	{ -EAGAIN, ADSP_EIMMEDIATE_STR},
	{ -EAGAIN, ADSP_ENOTIMPL_STR},
	{ -ENODATA, ADSP_ENEEDMORE_STR},
	{ -EADV, ADSP_ERR_MAX_STR},
	{ -ENOMEM, ADSP_ENOMEMORY_STR},
	{ -ENODEV, ADSP_ENOTEXIST_STR},
	{ -EADV, ADSP_ERR_MAX_STR},
};

static inline int adsp_err_get_lnx_err_code(u32 adsp_error)
{
	if (adsp_error > ADSP_ERR_MAX)
		return adsp_err_code_info[ADSP_ERR_MAX].lnx_err_code;
	else
		return adsp_err_code_info[adsp_error].lnx_err_code;
}

static inline char *adsp_err_get_err_str(u32 adsp_error)
{
	if (adsp_error > ADSP_ERR_MAX)
		return adsp_err_code_info[ADSP_ERR_MAX].adsp_err_str;
	else
		return adsp_err_code_info[adsp_error].adsp_err_str;
}

#endif
