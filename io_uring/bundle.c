// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "bundle.h"

/*
 * A bundle is a parent of a number of other requests. The bundle posts a
 * completions when ALL of the members of the bundle have completed. There's
 * no ordering between the members of the bundle, they can execute and complete
 * in parallel.
 */
struct io_bundle {
	struct file *file;
	bool serialized;
	/* number of members in bundle, plus parent */
	int refs;
	/* bundle done when it hits zero */
	union {
		atomic_t locked_completions;
		int completions;
	};
};

static bool __io_bundle_parent_put(struct io_bundle *bundle)
{
	if (bundle->serialized)
		return !--bundle->completions;
	return atomic_dec_and_test(&bundle->locked_completions);
}

static void io_bundle_parent_put(struct io_kiocb *req, unsigned issue_flags)
{
	struct io_bundle *bundle = io_kiocb_to_cmd(req, struct io_bundle);

	if (!__io_bundle_parent_put(bundle))
		return;

	io_req_complete_post(req, issue_flags);
}

void io_bundle_req_complete(struct io_kiocb *child, unsigned issue_flags)
{
	io_bundle_parent_put(child->link, issue_flags);
	child->link = NULL;
	child->flags &= ~REQ_F_BUNDLE;
}

struct io_kiocb *io_bundle_req_add(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_submit_state *state = &ctx->submit_state;
	struct io_submit_link *link = &state->link;
	struct io_kiocb *parent = state->parent;
	struct io_bundle *bundle = io_kiocb_to_cmd(parent, struct io_bundle);

	/*
	 * Ignore for the bundle parent, unless the bundle has no dependencies
	 */
	if (req == parent) {
		if (!(req->flags & (REQ_F_LINK | REQ_F_HARDLINK)))
			return req;
		return NULL;
	}

	req->flags |= REQ_F_BUNDLE;
	bundle->refs++;

	if (!link->head) {
		link->head = req;
		link->last = req;
	} else {
		link->last->link = req;
		link->last = req;
	}

	/*
	 * If link isn't set, chain is done.
	 */
	if (req->flags & (REQ_F_LINK | REQ_F_HARDLINK)) {
		req->flags &= ~(REQ_F_LINK | REQ_F_HARDLINK);
		return NULL;
	}

	return state->parent;
}

static bool io_bundle_init(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;

	if (sqe->ioprio || sqe->off || sqe->addr || sqe->len || sqe->rw_flags ||
	    sqe->personality || sqe->splice_fd_in || sqe->file_index ||
	    sqe->addr3)
		return true;
	if (req->flags & (REQ_F_FORCE_ASYNC | REQ_F_IO_DRAIN))
		return true;
	if (WARN_ON_ONCE(ctx->submit_state.parent))
		return true;
	return false;
}

int io_bundle_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_bundle *bundle = io_kiocb_to_cmd(req, struct io_bundle);
	struct io_ring_ctx *ctx = req->ctx;

	if (io_bundle_init(req, sqe)) {
		struct io_submit_link *link = &ctx->submit_state.link;

		/*
		 * Set these like for regular links, so error handling during
		 * init works.
		 */
		link->head = link->last = req;
		return -EINVAL;
	}

	req->link = NULL;
	ctx->submit_state.parent = req;
	bundle->refs = 1;
	return 0;
}

static void io_bundle_issue_req(struct io_kiocb *req, unsigned issue_flags)
{
	int ret;

	if (req->flags & REQ_F_FORCE_ASYNC) {
		ret = io_req_prep_async(req);
		if (ret)
			io_req_defer_failed(req, ret);
		else
			io_queue_iowq(req, NULL);
	} else {
		ret = io_issue_sqe(req, issue_flags);
		if (ret < 0)
			io_req_task_queue_fail(req, ret);
	}
}

/*
 * IORING_OP_NOP just posts a completion event, nothing else.
 */
int io_bundle(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_bundle *bundle = io_kiocb_to_cmd(req, struct io_bundle);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_submit_state *state = &ctx->submit_state;
	struct io_kiocb *cur;

	if (WARN_ON_ONCE(state->parent != req))
		return -EINVAL;

	state->parent = NULL;
	cur = state->link.head;
	state->link.head = NULL;
	io_req_set_res(req, bundle->refs - 1, 0);
	if (ctx->flags & IORING_SETUP_SINGLE_ISSUER) {
		bundle->serialized = true;
		bundle->completions = bundle->refs;
	} else {
		bundle->serialized = false;
		atomic_set(&bundle->locked_completions, bundle->refs);
	}

	while (cur) {
		struct io_kiocb *next;

		next = cur->link;
		cur->link = req;
		io_bundle_issue_req(cur, issue_flags);
		cur = next;
	}

	if (__io_bundle_parent_put(bundle))
		return IOU_OK;
	return IOU_ISSUE_SKIP_COMPLETE;
}
