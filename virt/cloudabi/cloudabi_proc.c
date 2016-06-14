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

#include <linux/binfmts.h>
#include <linux/capsicum.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>

#include "cloudabi_syscalls.h"
#include "cloudabi_types_common.h"
#include "cloudabi_util.h"

/* Converts CloudABI's signal numbers to Linux's. */
static cloudabi_errno_t convert_signal(cloudabi_signal_t in, int *out)
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
		return 0;
	} else {
		/* Invalid signal. */
		return CLOUDABI_EINVAL;
	}
}

/* Copies argument data to the stack of the new executable. */
static int copy_argdata(struct linux_binprm *bprm, const void *src,
    size_t srclen) {
	struct page *kmapped_page = NULL;
	unsigned long bytes_to_copy, dstpos, dstoff, kpos, i;
	const char *srcpos;
	char *kaddr;
	int ret;

	/* No arguments to be provided to the executable. */
	if (srclen == 0)
		return 0;

	/*
	 * Subtract space from the end to fit the argument data. As the
	 * kernel expects the arguments to be strings, but CloudABI
	 * argument data is binary safe, ensure null termination.
	 */
	dstpos = bprm->p;
	if (srclen >= dstpos--)
		return -E2BIG;
	bprm->p = dstpos - srclen;

	bprm->argc = 1;
	srcpos = (const char *)src + srclen;
	while (srclen > 0) {
		/* Cancellation point. */
		if (fatal_signal_pending(current)) {
			ret = -ERESTARTNOHAND;
			goto out;
		}
		cond_resched();

		/* Determine how much data to copy. */
		dstoff = dstpos % PAGE_SIZE;
		if (dstoff == 0)
			dstoff = PAGE_SIZE;
		bytes_to_copy = dstoff < srclen ? dstoff : srclen;

		dstpos -= bytes_to_copy;
		dstoff -= bytes_to_copy;
		srcpos -= bytes_to_copy;
		srclen -= bytes_to_copy;

		/* Map a new page if we've crossed the page boundary. */
		if (!kmapped_page || kpos != (dstpos & PAGE_MASK)) {
			struct page *page;

			page = get_arg_page(bprm, dstpos, 1);
			if (!page) {
				ret = -E2BIG;
				goto out;
			}

			if (kmapped_page) {
				flush_kernel_dcache_page(kmapped_page);
				kunmap(kmapped_page);
				put_arg_page(kmapped_page);
			}
			kmapped_page = page;
			kaddr = kmap(kmapped_page);
			kpos = dstpos & PAGE_MASK;
			flush_arg_page(bprm, kpos, kmapped_page);
		}

		/* Copy argument data into page. */
		if (copy_from_user(kaddr + dstoff, srcpos, bytes_to_copy)) {
			ret = -EFAULT;
			goto out;
		}

		/* Count number of null bytes, so that argc is correct. */
		for (i = 0; i < bytes_to_copy; ++i) {
			if (srcpos[i] == '\0')
				++bprm->argc;
		}
	}
	ret = 0;

out:
	/* Unmap page if still mapped. */
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}

cloudabi_errno_t cloudabi_sys_proc_exec(cloudabi_fd_t fd,
    const void __user *data, size_t datalen, const cloudabi_fd_t __user *fds,
    size_t fdslen)
{
	struct file *file;
	struct files_struct *old_files, *new_files;
	struct filename *filename;
	struct linux_binprm *bprm;
	int *new_fds;
	char *pathbuf = NULL;
	int error;

	/*
	 * Ensure that the new file descriptor table argument is of a
	 * limited size. The new file descriptor table cannot be larger
	 * than the existing one.
	 */
	old_files = current->files;
	if (fdslen > old_files->fdtab.max_fds)
		return CLOUDABI_EINVAL;

	/*
	 * Construct a new file descriptor table that has some of the
	 * original file descriptors remapped to a provided layout.
	 */
	new_fds = kmalloc(sizeof(int) * fdslen, GFP_KERNEL);
	if (new_fds == NULL)
		return CLOUDABI_ENOMEM;
	if (copy_from_user(new_fds, fds, sizeof(int) * fdslen)) {
		kfree(new_fds);
		return CLOUDABI_EFAULT;
	}
	new_files = remap_files_struct(old_files, new_fds, fdslen, &error);
	kfree(new_fds);
	if (new_files == NULL)
		return cloudabi_convert_errno(error);

	filename = getname_kernel("");
	if (IS_ERR(filename)) {
		error = PTR_ERR(filename);
		goto out_files;
	}

	if ((current->flags & PF_NPROC_EXCEEDED) &&
	    atomic_read(&current_user()->processes) > rlimit(RLIMIT_NPROC)) {
		error = -EAGAIN;
		goto out_filename;
	}

	/* We're below the limit (still or again), so we don't want to make
	 * further execve() calls fail. */
	current->flags &= ~PF_NPROC_EXCEEDED;

	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if (bprm == NULL) {
		error = -ENOMEM;
		goto out_filename;
	}

	error = prepare_bprm_creds(bprm);
	if (error != 0)
		goto out_free;

	check_unsafe_exec(bprm);
	current->in_execve = 1;

	file = do_open_execat(fd, filename, AT_EMPTY_PATH);
	error = PTR_ERR(file);
	if (IS_ERR(file))
		goto out_unmark;

	sched_exec();
	bprm->file = file;
	pathbuf = kasprintf(GFP_TEMPORARY, "/dev/fd/%u", fd);
	if (pathbuf == NULL) {
		error = -ENOMEM;
		goto out_unmark;
	}
	bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;
	bprm->filename = pathbuf;
	bprm->interp = bprm->filename;

	error = bprm_mm_init(bprm);
	if (error != 0)
		goto out_unmark;

	error = prepare_binprm(bprm);
	if (error < 0)
		goto out;

	error = copy_strings_kernel(1, &bprm->filename, bprm);
	if (error != 0)
		goto out;

	bprm->exec = bprm->p;

	/* Copy argument data to the new process. */
	error = copy_argdata(bprm, data, datalen);
	if (error != 0)
		goto out;

	error = exec_binprm(bprm);
	if (error != 0)
		goto out;

	/* execve succeeded */
	current->fs->in_exec = 0;
	current->in_execve = 0;
	acct_update_integrals(current);
	task_numa_free(current);
	free_bprm(bprm);
	kfree(pathbuf);
	putname(filename);
	reset_files_struct(new_files);
	return 0;

out:
	if (bprm->mm) {
		acct_arg_size(bprm, 0);
		mmput(bprm->mm);
	}

out_unmark:
	current->fs->in_exec = 0;
	current->in_execve = 0;

out_free:
	free_bprm(bprm);
	kfree(pathbuf);

out_filename:
	putname(filename);

out_files:
	put_files_struct(new_files);
	return cloudabi_convert_errno(error);
}

void cloudabi_sys_proc_exit(cloudabi_exitcode_t rval)
{
	sys_exit_group(rval);
}

cloudabi_errno_t cloudabi_sys_proc_fork(cloudabi_fd_t *fd, cloudabi_tid_t *tid)
{
	struct capsicum_rights rights;
	struct clone4_args clone4_args = {};
	struct clonefd_setup clonefd_setup = {};
	struct pt_regs *regs;
	struct task_struct *child;
	cloudabi_tid_t newtid;

	/* Create a new process. */
	cap_rights_init(&rights, CAP_FSTAT, CAP_PDWAIT);
	clonefd_setup.rights = &rights;
	child = copy_process(CLONE_FD, &clone4_args, NULL, 0, NUMA_NO_NODE,
	    &clonefd_setup);
	if (IS_ERR(child))
		return cloudabi_convert_errno(PTR_ERR(child));
	newtid = cloudabi_gettid(child);

	/* Return the new thread ID to the child process. */
	regs = task_pt_regs(child);
#ifdef __x86_64__
	regs->ax = CLOUDABI_PROCESS_CHILD;
	regs->dx = newtid;
#else
#error "Unknown architecture"
#endif

	/* Start execution of new process. */
	clonefd_install_fd(&clone4_args, &clonefd_setup);
	wake_up_new_task(child);

	/* Return the new file descriptor to the parent process. */
	*fd = clonefd_setup.fd;
	return 0;
}

cloudabi_errno_t cloudabi_sys_proc_raise(cloudabi_signal_t sig)
{
	int signum;
	cloudabi_errno_t error;

	error = convert_signal(sig, &signum);
	if (error != 0)
		return error;
	return cloudabi_convert_errno(sys_kill(task_tgid_vnr(current), signum));
}
