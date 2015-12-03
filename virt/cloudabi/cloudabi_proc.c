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

#include <linux/syscalls.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"
#include "cloudabi_util.h"

/* Converts CloudABI's signal numbers to Linux's. */
static cloudabi_errno_t
convert_signal(cloudabi_signal_t in, int *out)
{
	static const int signals[] = {
		[CLOUDABI_SIGABRT] = SIGABRT,
		[CLOUDABI_SIGALRM] = SIGALRM,
		[CLOUDABI_SIGBUS] = SIGBUS,
		[CLOUDABI_SIGCHLD] = SIGCHLD,
		[CLOUDABI_SIGCONT] = SIGCONT,
		[CLOUDABI_SIGFPE] = SIGFPE,
		[CLOUDABI_SIGHUP] = SIGHUP,
		[CLOUDABI_SIGILL] = SIGILL,
		[CLOUDABI_SIGINT] = SIGINT,
		[CLOUDABI_SIGKILL] = SIGKILL,
		[CLOUDABI_SIGPIPE] = SIGPIPE,
		[CLOUDABI_SIGQUIT] = SIGQUIT,
		[CLOUDABI_SIGSEGV] = SIGSEGV,
		[CLOUDABI_SIGSTOP] = SIGSTOP,
		[CLOUDABI_SIGSYS] = SIGSYS,
		[CLOUDABI_SIGTERM] = SIGTERM,
		[CLOUDABI_SIGTRAP] = SIGTRAP,
		[CLOUDABI_SIGTSTP] = SIGTSTP,
		[CLOUDABI_SIGTTIN] = SIGTTIN,
		[CLOUDABI_SIGTTOU] = SIGTTOU,
		[CLOUDABI_SIGURG] = SIGURG,
		[CLOUDABI_SIGUSR1] = SIGUSR1,
		[CLOUDABI_SIGUSR2] = SIGUSR2,
		[CLOUDABI_SIGVTALRM] = SIGVTALRM,
		[CLOUDABI_SIGXCPU] = SIGXCPU,
		[CLOUDABI_SIGXFSZ] = SIGXFSZ,
	};

	if ((in < sizeof(signals) / sizeof(signals[0]) && signals[in] != 0) ||
	    in == 0) {
		/* Valid signal mapping. */
		*out = signals[in];
		return (0);
	} else {
		/* Invalid signal. */
		return (CLOUDABI_EINVAL);
	}
}

cloudabi_errno_t cloudabi_sys_proc_exec(
    const struct cloudabi_sys_proc_exec_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_proc_exit(
    const struct cloudabi_sys_proc_exit_args *uap, unsigned long *retval) {
	return cloudabi_convert_errno(sys_exit_group(uap->rval));
}

cloudabi_errno_t cloudabi_sys_proc_fork(
    const void *uap, unsigned long *retval) {
#if 0
	struct clone4_args clone4_args = {};
	struct clonefd_setup clonefd_setup;
	struct pt_regs *regs;
	struct task_struct *child;
	cloudabi_tid_t tid;

	/* Create a new process. */
	child = copy_process(CLONE_FD, &clone4_args, NULL, 0, &clonefd_setup);
	if (IS_ERR(child))
		return cloudabi_convert_errno(PTR_ERR(child));
	tid = cloudabi_gettid(child);

	/* Return the new thread ID to the child process. */
	regs = task_pt_regs(child);
#ifdef __x86_64__
	/* TODO(ed): This should be solved more elegantly. */
	regs->di = CLOUDABI_PROCESS_CHILD;
	regs->si = tid;
#else
#error "Unknown architecture"
#endif

	/* Start execution of new process. */
	clonefd_install_fd(&clone4_args, &clonefd_setup);
	wake_up_new_task(child);

	/* Return the new file descriptor to the parent process. */
	retval[0] = clonefd_setup.fd;
	return 0;
#endif
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_proc_raise(
    const struct cloudabi_sys_proc_raise_args *uap, unsigned long *retval) {
	struct k_sigaction sigdfl = {
		.sa = {
			.sa_handler = SIG_DFL,
		},
	};
	int signum;
	cloudabi_errno_t error;

	error = convert_signal(uap->sig, &signum);
	if (error != 0)
		return error;

	/* Restore to default signal action and send signal. */
	do_sigaction(signum, &sigdfl, NULL);
	return cloudabi_convert_errno(sys_kill(task_tgid_vnr(current), signum));
}
