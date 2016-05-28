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

#include <linux/sched.h>
#include <linux/uaccess.h>

#include <asm/desc.h>
#include <asm/prctl.h>
#include <asm/proto.h>

#include "cloudabi_types_common.h"
#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

cloudabi_errno_t
cloudabi64_sys_thread_create(cloudabi64_threadattr_t __user *attr,
    cloudabi_tid_t *tid)
{
	cloudabi64_threadattr_t kattr;
	struct clone4_args clone4_args = {};
	struct clonefd_setup clonefd_setup = {};
	struct pt_regs *regs;
	struct task_struct *child;
	cloudabi_tid_t newtid;
	uint64_t tcb;
#ifdef __x86_64__
	uint64_t curtcbptr, newtcbptr;
#endif

	if (copy_from_user(&kattr, attr, sizeof(kattr)) != 0)
		return CLOUDABI_EFAULT;

	/* Keep some space for the TCB at the top of the stack. */
	tcb = rounddown(
	    kattr.stack + kattr.stack_size - sizeof(cloudabi64_tcb_t),
	    _Alignof(cloudabi64_tcb_t));

#ifdef __x86_64__
	/*
	 * Set up the %fs base on x86-64 to point to a single element
	 * array pointing to the TCB. This way userspace can modify the
	 * TLS area by modifying %fs:0.
	 */
	newtcbptr = rounddown(tcb - sizeof(uint64_t), _Alignof(uint64_t));
	if (copy_to_user((void __user *)newtcbptr, &tcb, sizeof(tcb)) != 0)
		return CLOUDABI_EFAULT;

	/*
	 * No easy way to adjust the %fs base after the new thread has
	 * been created. Temporarily set the %fs base of this thread to
	 * the desired value. We restore it right after thread creation
	 * has finished.
	 */
	if (current->thread.fsindex == FS_TLS_SEL)
		curtcbptr = get_desc_base(&current->thread.tls_array[FS_TLS]);
	else
		rdmsrl(MSR_FS_BASE, curtcbptr);
	do_arch_prctl(current, ARCH_SET_FS, newtcbptr);
#else
#error "Unknown architecture"
#endif

	/* Create a new thread. */
	child = copy_process(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	    CLONE_THREAD, &clone4_args, NULL, 0, &clonefd_setup);
#ifdef __x86_64__
	do_arch_prctl(current, ARCH_SET_FS, curtcbptr);
#endif
	if (IS_ERR(child))
		return cloudabi_convert_errno(PTR_ERR(child));
	newtid = cloudabi_gettid(child);

	/* Set initial registers. */
	regs = task_pt_regs(child);
#ifdef __x86_64__
	regs->sp = rounddown(newtcbptr, 16) - 8;
	regs->ip = kattr.entry_point;
	regs->di = newtid;
	regs->si = kattr.argument;
#else
#error "Unknown architecture"
#endif

	/* Start execution of new thread. */
	wake_up_new_task(child);

	*tid = newtid;
	return 0;
}
