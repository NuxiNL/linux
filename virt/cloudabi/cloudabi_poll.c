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
#include <linux/hrtimer.h>
#include <linux/slab.h>

#include "cloudabi_util.h"

struct cloudabi_poll {
	int dummy;
};

static void cloudabi_poll_init(struct cloudabi_poll *cp)
{
	/* TODO(ed): Implement! */
}

static void cloudabi_poll_destroy(struct cloudabi_poll *cp)
{
	/* TODO(ed): Implement! */
}

static int cloudabi_poll_release(struct inode *inode, struct file *file)
{
	struct cloudabi_poll *cp;

	cp = file->private_data;
	cloudabi_poll_destroy(cp);
	kfree(cp);
	return 0;
}

static const struct file_operations cloudabi_poll_fops = {
	.release	= cloudabi_poll_release,
};

cloudabi_errno_t cloudabi_poll_create(cloudabi_fd_t *fd)
{
	struct capsicum_rights rights;
	struct cloudabi_poll *cp;
	struct file *file, *installfile;
	int error;

	/* Allocate a file descriptor. */
	error = get_unused_fd_flags(0);
	if (error < 0)
		return cloudabi_convert_errno(error);
	*fd = error;

	/* Allocate a polling object. */
	cp = kmalloc(sizeof(*cp), GFP_KERNEL);
	if (cp == NULL) {
		put_unused_fd(*fd);
		return CLOUDABI_ENOMEM;
	}

	/* Create the anonymous inode to be placed underneath. */
	file = anon_inode_getfile("[cloudabi_poll]", &cloudabi_poll_fops, cp,
				  0);
	if (IS_ERR(file)) {
		put_unused_fd(*fd);
		kfree(cp);
		return cloudabi_convert_errno(PTR_ERR(file));
	}

	/* Restrict rights. */
	cap_rights_init(&rights, CAP_FSTAT, CAP_KQUEUE);
	installfile = capsicum_file_install(&rights, file);
	if (IS_ERR(installfile)) {
		put_unused_fd(*fd);
		kfree(cp);
		fput(file);
		return cloudabi_convert_errno(PTR_ERR(installfile));
	}

	cloudabi_poll_init(cp);
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

static bool do_pdwait(const cloudabi_subscription_t *sub,
                      cloudabi_event_t *ev, bool wnohang) {
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

cloudabi_errno_t cloudabi_sys_poll(const void __user *in, void __user *out,
    size_t nsubscriptions, size_t *nevents,
    const struct cloudabi_poll_copyops *copyops)
{
	struct cloudabi_poll cp;
	struct timespec ts;
	struct task_struct *task;
	clockid_t clockid;
	cloudabi_errno_t error;
	enum hrtimer_mode mode;

	/*
	 * Bandaid to support CloudABI futex constructs.
	 */
	task = current;
	if (nsubscriptions == 1) {
		cloudabi_subscription_t sub;
		cloudabi_event_t ev = {};

		error = copyops->copyin(in, 0, &sub);
		if (error != 0)
			return error;
		ev.userdata = sub.userdata;
		ev.type = sub.type;
		if (sub.type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Sleep. */
			/* TODO(ed): Remove this once polling works. */
			mode = sub.clock.flags & CLOUDABI_SUBSCRIPTION_CLOCK_ABSTIME ?
			    HRTIMER_MODE_ABS : HRTIMER_MODE_REL;
			ev.error = cloudabi_convert_clockid(sub.clock.clock_id,
			    &clockid);
			if (ev.error == 0) {
				ts.tv_sec = sub.clock.timeout / NSEC_PER_SEC;
				ts.tv_nsec = sub.clock.timeout % NSEC_PER_SEC;
				ev.error = cloudabi_convert_errno(
				    hrtimer_nanosleep(&ts, NULL, mode,
				        clockid));
			}
			*nevents = 1;
			return copyops->copyout(&ev, out, 0);
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
			return copyops->copyout(&ev, out, 0);
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK) {
			/* Acquire a read lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_rdlock(
			        task, (cloudabi_lock_t *)sub.lock.lock,
			        sub.lock.lock_scope, CLOUDABI_CLOCK_MONOTONIC,
			        UINT64_MAX, 0));
			*nevents = 1;
			return copyops->copyout(&ev, out, 0);
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK) {
			/* Acquire a write lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_wrlock(
			        task, (cloudabi_lock_t *)sub.lock.lock,
			        sub.lock.lock_scope, CLOUDABI_CLOCK_MONOTONIC,
			        UINT64_MAX, 0));
			*nevents = 1;
			return copyops->copyout(&ev, out, 0);
		} else if (sub.type == CLOUDABI_EVENTTYPE_PROC_TERMINATE) {
			/* Wait for process termination. */
			/* TODO(ed): Remove this once polling works. */
			do_pdwait(&sub, &ev, false);
			*nevents = 1;
			return copyops->copyout(&ev, out, 0);
		}
	} else if (nsubscriptions == 2) {
		cloudabi_subscription_t sub[2];
		cloudabi_event_t ev[2] = {};

		error = copyops->copyin(in, 0, &sub[0]);
		if (error != 0)
			return error;
		error = copyops->copyin(in, 1, &sub[1]);
		if (error != 0)
			return error;
		ev[0].userdata = sub[0].userdata;
		ev[0].type = sub[0].type;
		ev[1].userdata = sub[1].userdata;
		ev[1].type = sub[1].type;
		if (sub[0].type == CLOUDABI_EVENTTYPE_CONDVAR &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Wait for a condition variable with timeout. */
			ev[0].error = cloudabi_convert_errno(
			    cloudabi_futex_condvar_wait(
			        task,
			        (cloudabi_condvar_t *)sub[0].condvar.condvar,
			        sub[0].condvar.condvar_scope,
			        (cloudabi_lock_t *)sub[0].condvar.lock,
			        sub[0].condvar.lock_scope,
			        sub[1].clock.clock_id, sub[1].clock.timeout,
			        sub[1].clock.precision));
			*nevents = 1;
			if (ev[0].error == CLOUDABI_ETIMEDOUT)
				return copyops->copyout(&ev[1], out, 0);
			*nevents = 1;
			return copyops->copyout(&ev[0], out, 0);
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Acquire a read lock with a timeout. */
			ev[0].error = cloudabi_convert_errno(
			    cloudabi_futex_lock_rdlock(
			        task, (cloudabi_lock_t *)sub[0].lock.lock,
			        sub[0].lock.lock_scope, sub[1].clock.clock_id,
			        sub[1].clock.timeout, sub[1].clock.precision));
			*nevents = 1;
			if (ev[0].error == CLOUDABI_ETIMEDOUT)
				return copyops->copyout(&ev[1], out, 0);
			return copyops->copyout(&ev[0], out, 0);
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Acquire a write lock with a timeout. */
			ev[0].error = cloudabi_convert_errno(
			    cloudabi_futex_lock_wrlock(
			        task, (cloudabi_lock_t *)sub[0].lock.lock,
			        sub[0].lock.lock_scope, sub[1].clock.clock_id,
			        sub[1].clock.timeout, sub[1].clock.precision));
			*nevents = 1;
			if (ev[0].error == CLOUDABI_ETIMEDOUT)
				return copyops->copyout(&ev[1], out, 0);
			return copyops->copyout(&ev[0], out, 0);
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_PROC_TERMINATE &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK &&
		    sub[1].clock.timeout == 0) {
			/* Wait for process termination. */
			/* TODO(ed): Remove this once polling works. */
			*nevents = 1;
			if (!do_pdwait(&sub[0], &ev[0], true))
				return copyops->copyout(&ev[1], out, 0);
			return copyops->copyout(&ev[0], out, 0);
		}
	}

	cloudabi_poll_init(&cp);
	error = cloudabi_poll(&cp, in, nsubscriptions, out, nsubscriptions,
	                      NULL, nevents, copyops);
	cloudabi_poll_destroy(&cp);
	return error;
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
