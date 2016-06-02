/*-
 * Copyright (c) 2016 Nuxi, https://nuxi.nl/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <linux/anon_inodes.h>
#include <linux/capsicum.h>
#include <linux/file.h>
#include <linux/fs.h>

#include "cloudabi_util.h"

struct cloudabi_poll {
	int dummy;
};

static const struct file_operations cloudabi_poll_fops = {
};

cloudabi_errno_t cloudabi_poll_create(cloudabi_fd_t *fd)
{
	struct capsicum_rights rights;
	struct file *file, *installfile;
	int error;

	/* Allocate a file descriptor. */
	error = get_unused_fd_flags(0);
	if (error < 0)
		return cloudabi_convert_errno(error);
	*fd = error;

	/* Create the anonymous inode to be placed underneath. */
	/* TODO(ed): Allocate actual polling object. */
	file = anon_inode_getfile("[cloudabi_poll]", &cloudabi_poll_fops, NULL,
				  0);
	if (IS_ERR(file)) {
		put_unused_fd(*fd);
		return cloudabi_convert_errno(PTR_ERR(file));
	}

	/* Restrict rights. */
	cap_rights_init(&rights, CAP_FSTAT, CAP_KQUEUE);
	installfile = capsicum_file_install(&rights, file);
	if (IS_ERR(installfile)) {
		put_unused_fd(*fd);
		fput(file);
		return cloudabi_convert_errno(PTR_ERR(installfile));
	}

	fd_install(*fd, installfile);
	return 0;
}

bool cloudabi_is_poll(struct file *f)
{
	return f->f_op == &cloudabi_poll_fops;
}

static cloudabi_errno_t cloudabi_poll(struct cloudabi_poll *cp,
    const void __user *in, size_t nin, void __user *out, size_t nout,
    const void __user *timeout, size_t *nevents,
    const struct cloudabi_poll_copyops *copyops)
{
	/* TODO(ed): Implement! */
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_poll(const void __user *in, void __user *out,
    size_t nsubscriptions, size_t *nevents,
    const struct cloudabi_poll_copyops *copyops)
{
	/* TODO(ed): Implement! */
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_poll_fd(cloudabi_fd_t fd,
    const void __user *in, size_t nin, void __user *out, size_t nout,
    const void __user *timeout, size_t *nevents,
    const struct cloudabi_poll_copyops *copyops)
{
	struct capsicum_rights rights;
	struct fd f;
	cloudabi_errno_t error;

	/* Determine rights that need to be present. */
	cap_rights_init(&rights);
	if (nin > 0)
		cap_rights_set(&rights, CAP_KQUEUE_CHANGE);
	if (nout > 0)
		cap_rights_set(&rights, CAP_KQUEUE_EVENT);

	/* Fetch file descriptor. */
	f = fdget_rights(fd, &rights);
	if (IS_ERR(f.file))
		return cloudabi_convert_errno(PTR_ERR(f.file));

	/* Perform polling call if valid. */
	if (cloudabi_is_poll(f.file))
		error = cloudabi_poll(f.file->private_data, in, nin, out, nout,
				      timeout, nevents, copyops);
	else
		error = CLOUDABI_EBADF;
	fdput(f);
	return error;
}
