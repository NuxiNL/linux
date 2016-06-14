/*-
 * Copyright (c) 2015 Nuxi, https://nuxi.nl/
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

#include <linux/capsicum.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "cloudabi_types_common.h"
#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

cloudabi_errno_t cloudabi64_sys_sock_recv(cloudabi_fd_t sock,
    const cloudabi64_recv_in_t __user *in, cloudabi64_recv_out_t __user *out)
{
	struct capsicum_rights rights;
	struct fd f_sock;
	struct msghdr msg = {};
	cloudabi64_recv_in_t ri;
	cloudabi64_recv_out_t ro = {};
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct socket *sk;
	int error;

	if (copy_from_user(&ri, in, sizeof(ri)) != 0)
		return CLOUDABI_EFAULT;

	/* Obtain socket. */
	cap_rights_init(&rights, CAP_RECV);
	f_sock = fdget_raw_rights(sock, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sk = sock_from_file(f_sock.file, &error);
	if (sk == NULL)
		goto out;

	/* Process ri_data and ri_datalen. */
	error = import_iovec(WRITE, (const struct iovec __user *)ri.ri_data,
	                     ri.ri_datalen, ARRAY_SIZE(iovstack), &iov,
	                     &msg.msg_iter);
	if (error != 0)
		goto out;

	/* Convert ri_flags. */
	if (ri.ri_flags & CLOUDABI_MSG_PEEK)
		msg.msg_flags |= MSG_PEEK;
	if (ri.ri_flags & CLOUDABI_MSG_WAITALL)
		msg.msg_flags |= MSG_WAITALL;
	if (sk->file->f_flags & O_NONBLOCK)
		msg.msg_flags |= MSG_DONTWAIT;

	/* Read message. Return length of read message. */
	error = sock_recvmsg(sk, &msg, msg.msg_flags);
	if (error >= 0) {
		ro.ro_datalen = error;
		error = copy_to_user(out, &ro, sizeof(ro)) != 0 ? -EFAULT : 0;
	}
	kfree(iov);
out:
	fdput(f_sock);
	return cloudabi_convert_errno(error);
}

cloudabi_errno_t cloudabi64_sys_sock_send(cloudabi_fd_t sock,
    const cloudabi64_send_in_t __user *in, cloudabi64_send_out_t __user *out)
{
	struct capsicum_rights rights;
	struct fd f_sock;
	struct msghdr msg = {};
	cloudabi64_send_in_t si;
	cloudabi64_send_out_t so = {};
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct socket *sk;
	int error;

	if (copy_from_user(&si, in, sizeof(si)) != 0)
		return CLOUDABI_EFAULT;

	/* Obtain socket. */
	cap_rights_init(&rights, CAP_SEND);
	f_sock = fdget_raw_rights(sock, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sk = sock_from_file(f_sock.file, &error);
	if (sk == NULL)
		goto out;

	/* Process si_data and si_datalen. */
	error = import_iovec(WRITE, (const struct iovec __user *)si.si_data,
	                     si.si_datalen, ARRAY_SIZE(iovstack), &iov,
	                     &msg.msg_iter);
	if (error != 0)
		goto out;

	/* TODO(ed): Process si_fds and si_fdslen. */

	/* Process si_flags. */
	msg.msg_flags = MSG_NOSIGNAL;
	if (si.si_flags & CLOUDABI_MSG_EOR)
		msg.msg_flags |= MSG_EOR;
	if (sk->file->f_flags & O_NONBLOCK)
		msg.msg_flags |= MSG_DONTWAIT;

	/* Write message. Return length of written message. */
	error = sock_sendmsg(sk, &msg);
	if (error >= 0) {
		so.so_datalen = error;
		error = copy_to_user(out, &so, sizeof(so)) != 0 ? -EFAULT : 0;
	}
	kfree(iov);
out:
	fdput(f_sock);
	return cloudabi_convert_errno(error);
}
