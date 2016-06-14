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

#include <asm/ptrace.h>

#include "cloudabi_types_common.h"
#include "cloudabi64_syscalls_table.h"
#include "cloudabi64_util.h"

void cloudabi64_syscall_handler(struct pt_regs *regs)
{
	uint64_t in[] = {
	    regs->di, regs->si, regs->dx, regs->r10, regs->r8, regs->r9,
	};
	uint64_t out[] = { 0, regs->dx };
	size_t nr;
	cloudabi_errno_t error;

	nr = regs->orig_ax;
	if (nr >= sizeof(syscalls) / sizeof(syscalls[0]))
		error = CLOUDABI_ENOSYS;
	else
		error = syscalls[nr](in, out);
	if (error == 0) {
		regs->flags &= ~1;
		regs->ax = out[0];
		regs->dx = out[1];
	} else {
		regs->flags |= 1;
		regs->ax = error;
	}
}
