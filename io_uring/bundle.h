// SPDX-License-Identifier: GPL-2.0

int io_bundle_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_bundle(struct io_kiocb *req, unsigned int issue_flags);
struct io_kiocb *io_bundle_req_add(struct io_kiocb *req);
void io_bundle_req_complete(struct io_kiocb *req, unsigned issue_flags);
