/*-
 * Copyright (c) 2015-2016 Nuxi, https://nuxi.nl/
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

#include <linux/uaccess.h>

#include "cloudabi_types_common.h"
#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

cloudabi_errno_t cloudabi64_poll_copyin(const void __user *base, size_t idx,
                                        cloudabi_subscription_t *out)
{
	const cloudabi64_subscription_t __user *in;

	_Static_assert(sizeof(*in) == sizeof(*out),
	    "This code assumes a 64-bit system");
	in = base;
	return copy_from_user(out, in + idx, sizeof(*out)) != 0 ?
	    CLOUDABI_EFAULT : 0;
}

cloudabi_errno_t cloudabi64_poll_copyout(const cloudabi_event_t *in,
                                         void __user *base, size_t idx)
{
	cloudabi64_event_t __user *out;

	_Static_assert(sizeof(*in) == sizeof(*out),
	    "This code assumes a 64-bit system");
	out = base;
	return copy_to_user(out + idx, in, sizeof(*in)) != 0 ?
	    CLOUDABI_EFAULT : 0;
}

static const struct cloudabi_poll_copyops copyops = {
	.copyin		= cloudabi64_poll_copyin,
	.copyout	= cloudabi64_poll_copyout,
};

cloudabi_errno_t cloudabi64_sys_poll(const cloudabi64_subscription_t __user *in,
    cloudabi64_event_t __user *out, size_t nsubscriptions, size_t *nevents)
{
	return cloudabi_sys_poll(in, out, nsubscriptions, nevents, &copyops);
}

cloudabi_errno_t cloudabi64_sys_poll_fd(cloudabi_fd_t fd,
    const cloudabi64_subscription_t __user *in, size_t nin,
    cloudabi64_event_t __user *out, size_t nout,
    const cloudabi64_subscription_t __user *timeout, size_t *nevents)
{
	return cloudabi_sys_poll_fd(fd, in, nin, out, nout, timeout, nevents,
	                            &copyops);
}
