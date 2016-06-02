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

#include <linux/hrtimer.h>
#include <linux/uaccess.h>

#include "cloudabi_types_common.h"
#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

static cloudabi_signal_t
convert_signal(int sig)
{
	static const cloudabi_signal_t signals[] = {
		[SIGABRT]	= CLOUDABI_SIGABRT,
		[SIGALRM]	= CLOUDABI_SIGALRM,
		[SIGBUS]	= CLOUDABI_SIGBUS,
		[SIGCHLD]	= CLOUDABI_SIGCHLD,
		[SIGCONT]	= CLOUDABI_SIGCONT,
		[SIGFPE]	= CLOUDABI_SIGFPE,
		[SIGHUP]	= CLOUDABI_SIGHUP,
		[SIGILL]	= CLOUDABI_SIGILL,
		[SIGINT]	= CLOUDABI_SIGINT,
		[SIGKILL]	= CLOUDABI_SIGKILL,
		[SIGPIPE]	= CLOUDABI_SIGPIPE,
		[SIGQUIT]	= CLOUDABI_SIGQUIT,
		[SIGSEGV]	= CLOUDABI_SIGSEGV,
		[SIGSTOP]	= CLOUDABI_SIGSTOP,
		[SIGSYS]	= CLOUDABI_SIGSYS,
		[SIGTERM]	= CLOUDABI_SIGTERM,
		[SIGTRAP]	= CLOUDABI_SIGTRAP,
		[SIGTSTP]	= CLOUDABI_SIGTSTP,
		[SIGTTIN]	= CLOUDABI_SIGTTIN,
		[SIGTTOU]	= CLOUDABI_SIGTTOU,
		[SIGURG]	= CLOUDABI_SIGURG,
		[SIGUSR1]	= CLOUDABI_SIGUSR1,
		[SIGUSR2]	= CLOUDABI_SIGUSR2,
		[SIGVTALRM]	= CLOUDABI_SIGVTALRM,
		[SIGXCPU]	= CLOUDABI_SIGXCPU,
		[SIGXFSZ]	= CLOUDABI_SIGXFSZ,
	};

	/* Convert unknown signals to SIGABRT. */
	if (sig < 0 || sig >= ARRAY_SIZE(signals) || signals[sig] == 0)
		return (SIGABRT);
	return (signals[sig]);
}

static bool do_pdwait(const cloudabi64_subscription_t *sub,
                      cloudabi64_event_t *ev, bool wnohang) {
	int error, exit_code;
	int32_t code, status;

	error = clonefd_wait(sub->proc_terminate.fd, wnohang, &exit_code);
	ev->proc_terminate.fd = sub->proc_terminate.fd;
	ev->error = cloudabi_convert_errno(error);
	if (error == 0) {
		task_exit_code_status(exit_code, &code, &status);
		if (code == CLD_EXITED)
			ev->proc_terminate.exitcode = status;
		else
			ev->proc_terminate.signal = convert_signal(status);
	}
	return error != -EAGAIN;
}

cloudabi_errno_t cloudabi64_poll_copyin(const void __user *base, size_t idx,
                                        cloudabi_subscription_t *out)
{
	const cloudabi_subscription_t __user *in;

	_Static_assert(sizeof(cloudabi_subscription_t) ==
	    sizeof(cloudabi64_subscription_t),
	    "This code assumes a 64-bit system");
	in = base;
	return copy_from_user(out, in + idx, sizeof(*out)) != 0 ?
	    CLOUDABI_EFAULT : 0;
}

cloudabi_errno_t cloudabi64_poll_copyout(const cloudabi_event_t *in,
                                         void __user *base, size_t idx)
{
	cloudabi_event_t __user *out;

	_Static_assert(sizeof(cloudabi_event_t) ==
	    sizeof(cloudabi64_event_t),
	    "This code assumes a 64-bit system");
	out = base;
	return copy_from_user(out + idx, in, sizeof(*in)) != 0 ?
	    CLOUDABI_EFAULT : 0;
}

static const struct cloudabi_poll_copyops copyops = {
	.copyin		= cloudabi64_poll_copyin,
	.copyout	= cloudabi64_poll_copyout,
};

cloudabi_errno_t
cloudabi64_sys_poll(const cloudabi64_subscription_t __user *in,
    cloudabi64_event_t __user *out, size_t nsubscriptions, size_t *nevents)
{
	enum hrtimer_mode mode;
	struct timespec ts;
	struct task_struct *task;
	int error;
	clockid_t clockid;

	/*
	 * Bandaid to support CloudABI futex constructs.
	 */
	task = current;
	if (nsubscriptions == 1) {
		cloudabi64_subscription_t sub;
		cloudabi64_event_t ev = {};

		if (copy_from_user(&sub, in, sizeof(sub)) != 0)
			return CLOUDABI_EFAULT;
		ev.userdata = sub.userdata;
		ev.type = sub.type;
		if (sub.type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Sleep. */
			/* TODO(ed): Remove this once polling works. */
			mode = sub.clock.flags & CLOUDABI_SUBSCRIPTION_CLOCK_ABSTIME ?
			    HRTIMER_MODE_ABS : HRTIMER_MODE_REL;
			error = cloudabi_convert_clockid(sub.clock.clock_id,
			    &clockid);
			if (error == 0) {
				ts.tv_sec = sub.clock.timeout / NSEC_PER_SEC;
				ts.tv_nsec = sub.clock.timeout % NSEC_PER_SEC;
				error = hrtimer_nanosleep(&ts, NULL, mode,
				    clockid);
			}
			ev.error = cloudabi_convert_errno(error);
			*nevents = 1;
			return copy_to_user(out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (sub.type == CLOUDABI_EVENTTYPE_CONDVAR) {
			/* Wait on a condition variable. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_condvar_wait(
			        task, (cloudabi_condvar_t *)sub.condvar.condvar,
			        sub.condvar.condvar_scope,
			        (cloudabi_lock_t *)sub.condvar.lock,
			        sub.condvar.lock_scope,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			*nevents = 1;
			return copy_to_user(out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK) {
			/* Acquire a read lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_rdlock(
			        task, (cloudabi_lock_t *)sub.lock.lock,
			        sub.lock.lock_scope, CLOUDABI_CLOCK_MONOTONIC,
			        UINT64_MAX, 0));
			*nevents = 1;
			return copy_to_user(out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK) {
			/* Acquire a write lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_wrlock(
			        task, (cloudabi_lock_t *)sub.lock.lock,
			        sub.lock.lock_scope, CLOUDABI_CLOCK_MONOTONIC,
			        UINT64_MAX, 0));
			*nevents = 1;
			return copy_to_user(out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (sub.type == CLOUDABI_EVENTTYPE_PROC_TERMINATE) {
			/* Wait for process termination. */
			/* TODO(ed): Remove this once polling works. */
			do_pdwait(&sub, &ev, false);
			*nevents = 1;
			return copy_to_user(out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		}
	} else if (nsubscriptions == 2) {
		cloudabi64_subscription_t sub[2];
		cloudabi64_event_t ev[2] = {};

		if (copy_from_user(&sub, in, sizeof(sub)) != 0)
			return CLOUDABI_EFAULT;
		ev[0].userdata = sub[0].userdata;
		ev[0].type = sub[0].type;
		ev[1].userdata = sub[1].userdata;
		ev[1].type = sub[1].type;
		if (sub[0].type == CLOUDABI_EVENTTYPE_CONDVAR &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Wait for a condition variable with timeout. */
			error = cloudabi_futex_condvar_wait(
			    task, (cloudabi_condvar_t *)sub[0].condvar.condvar,
			    sub[0].condvar.condvar_scope,
			    (cloudabi_lock_t *)sub[0].condvar.lock,
			    sub[0].condvar.lock_scope,
			    sub[1].clock.clock_id, sub[1].clock.timeout,
			    sub[1].clock.precision);
			if (error == -ETIMEDOUT) {
				ev[1].error = 0;
				*nevents = 1;
				return copy_to_user(out, &ev[1],
				    sizeof(ev[1])) != 0 ? CLOUDABI_EFAULT : 0;
			}

			ev[0].error = cloudabi_convert_errno(error);
			*nevents = 1;
			return copy_to_user(out, &ev[0],
			    sizeof(ev[0])) != 0 ? CLOUDABI_EFAULT : 0;
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Acquire a read lock with a timeout. */
			error = cloudabi_futex_lock_rdlock(
			    task, (cloudabi_lock_t *)sub[0].lock.lock,
			    sub[0].lock.lock_scope, sub[1].clock.clock_id,
			    sub[1].clock.timeout, sub[1].clock.precision);
			if (error == -ETIMEDOUT) {
				ev[1].error = 0;
				*nevents = 1;
				return copy_to_user(out, &ev[1],
				    sizeof(ev[1])) != 0 ? CLOUDABI_EFAULT : 0;
			}

			ev[0].error = cloudabi_convert_errno(error);
			*nevents = 1;
			return copy_to_user(out, &ev[0],
			    sizeof(ev[0])) != 0 ? CLOUDABI_EFAULT : 0;
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Acquire a write lock with a timeout. */
			error = cloudabi_futex_lock_wrlock(
			    task, (cloudabi_lock_t *)sub[0].lock.lock,
			    sub[0].lock.lock_scope, sub[1].clock.clock_id,
			    sub[1].clock.timeout, sub[1].clock.precision);
			if (error == -ETIMEDOUT) {
				ev[1].error = 0;
				*nevents = 1;
				return copy_to_user(out, &ev[1],
				    sizeof(ev[1])) != 0 ? CLOUDABI_EFAULT : 0;
			}

			ev[0].error = cloudabi_convert_errno(error);
			*nevents = 1;
			return copy_to_user(out, &ev[0],
			    sizeof(ev[0])) != 0 ? CLOUDABI_EFAULT : 0;
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_PROC_TERMINATE &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK &&
		    sub[1].clock.timeout == 0) {
			/* Wait for process termination. */
			/* TODO(ed): Remove this once polling works. */
			if (!do_pdwait(&sub[0], &ev[0], true)) {
				ev[1].error = 0;
				*nevents = 1;
				return copy_to_user(out, &ev[1],
				    sizeof(ev[1])) != 0 ? CLOUDABI_EFAULT : 0;
			}

			*nevents = 1;
			return copy_to_user(out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		}
	}

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
