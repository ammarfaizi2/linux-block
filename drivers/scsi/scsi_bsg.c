// SPDX-License-Identifier: GPL-2.0
#include <linux/bsg.h>
#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/sg.h>
#include "scsi_priv.h"

#define uptr64(val) ((void __user *)(uintptr_t)(val))

static int scsi_bsg_sg_io_fn(struct request_queue *q, struct sg_io_v4 *hdr,
		fmode_t mode, unsigned int timeout)
{
	struct scsi_cmnd *scmd;
	unsigned char cmnd[sizeof(scmd->cmnd)];
	unsigned char sense[SCSI_SENSE_BUFFERSIZE];
	int sense_len = 0;
	blk_opf_t opf = hdr->dout_xfer_len ?  REQ_OP_DRV_OUT : REQ_OP_DRV_IN;
	struct request *rq;
	struct bio *bio = NULL;

	if (hdr->protocol != BSG_PROTOCOL_SCSI  ||
	    hdr->subprotocol != BSG_SUB_PROTOCOL_SCSI_CMD)
		return -EINVAL;
	if (hdr->dout_xfer_len && hdr->din_xfer_len) {
		pr_warn_once("BIDI support in bsg has been removed.\n");
		return -EOPNOTSUPP;
	}
	if (hdr->request_len > sizeof(cmnd))
		return -EINVAL;
	if (copy_from_user(cmnd, uptr64(hdr->request), hdr->request_len))
		return -EFAULT;
	if (!scsi_cmd_allowed(cmnd, mode))
		return -EPERM;

	if (hdr->dout_xfer_len)
		bio = blk_map_user(q, opf, NULL, uptr64(hdr->dout_xferp),
				hdr->dout_xfer_len);
	else if (hdr->din_xfer_len)
		bio = blk_map_user(q, opf, NULL, uptr64(hdr->din_xferp),
				hdr->din_xfer_len);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	rq = scsi_alloc_request(q, opf, 0);
	if (IS_ERR(rq)) {
		blk_rq_unmap_user(bio);
		return PTR_ERR(rq);
	}
	rq->timeout = timeout;

	scmd = blk_mq_rq_to_pdu(rq);
	scmd->cmd_len = hdr->request_len;
	memcpy(scmd->cmnd, cmnd, scmd->cmd_len);
	blk_rq_attach_bios(rq, bio);

	blk_execute_rq(rq, !(hdr->flags & BSG_FLAG_Q_AT_TAIL));

	/*
	 * fill in all the output members
	 */
	hdr->device_status = scmd->result & 0xff;
	hdr->transport_status = host_byte(scmd->result);
	hdr->driver_status = 0;
	if (scsi_status_is_check_condition(scmd->result))
		hdr->driver_status = DRIVER_SENSE;
	hdr->info = 0;
	if (hdr->device_status || hdr->transport_status || hdr->driver_status)
		hdr->info |= SG_INFO_CHECK;

	if (scmd->sense_len && hdr->response) {
		sense_len = min_t(unsigned int, hdr->max_response_len,
				scmd->sense_len);
		memcpy(sense, scmd->sense_buffer, sense_len);
	}

	if (rq_data_dir(rq) == READ)
		hdr->din_resid = scmd->resid_len;
	else
		hdr->dout_resid = scmd->resid_len;

	blk_mq_free_request(rq);
	blk_rq_unmap_user(bio);
	if (sense_len && copy_to_user(uptr64(hdr->response), sense, sense_len))
		return -EFAULT;

	hdr->response_len = sense_len;
	return 0;
}

struct bsg_device *scsi_bsg_register_queue(struct scsi_device *sdev)
{
	return bsg_register_queue(sdev->request_queue, &sdev->sdev_gendev,
			dev_name(&sdev->sdev_gendev), scsi_bsg_sg_io_fn);
}
