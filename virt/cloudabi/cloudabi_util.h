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

#ifndef CLOUDABI_UTIL_H
#define CLOUDABI_UTIL_H

#include "cloudabi_types.h"

struct capsicum_rights;
struct file;
struct task_struct;

/* Limits. */
#define UINT64_MAX (~(uint64_t)0)

#define cloudabi_gettid task_pid_vnr

cloudabi_errno_t cloudabi_convert_errno(int);

/* Extracts the CloudABI file descriptor type from st_mode. */
cloudabi_filetype_t cloudabi_convert_filetype_simple(umode_t);

/* Converts a file descriptor to a CloudABI file descriptor type. */
cloudabi_filetype_t cloudabi_convert_filetype(struct file *);

/* Fetches the time value of a clock. */
int cloudabi_clock_time_get(cloudabi_clockid_t, cloudabi_timestamp_t *);

/* Converts a CloudABI clock ID to a Linux clock ID. */
cloudabi_errno_t cloudabi_convert_clockid(cloudabi_clockid_t, clockid_t *);

/* Converts CloudABI rights to a set of Capsicum capabilities. */
cloudabi_errno_t cloudabi_convert_rights(cloudabi_rights_t in,
                                         struct capsicum_rights *out);

/* Removes rights that conflict with the file descriptor type. */
void cloudabi_remove_conflicting_rights(cloudabi_filetype_t filetype,
    cloudabi_rights_t *base, cloudabi_rights_t *inheriting);

/*
 * Blocking futex functions.
 *
 * These functions are called by CloudABI's polling system calls to
 * sleep on a lock or condition variable.
 */
int cloudabi_futex_condvar_wait(struct task_struct *, cloudabi_condvar_t *,
    cloudabi_scope_t, cloudabi_lock_t *, cloudabi_scope_t, cloudabi_clockid_t,
    cloudabi_timestamp_t, cloudabi_timestamp_t);
int cloudabi_futex_lock_rdlock(struct task_struct *, cloudabi_lock_t *,
    cloudabi_scope_t, cloudabi_clockid_t, cloudabi_timestamp_t,
    cloudabi_timestamp_t);
int cloudabi_futex_lock_wrlock(struct task_struct *, cloudabi_lock_t *,
    cloudabi_scope_t, cloudabi_clockid_t, cloudabi_timestamp_t,
    cloudabi_timestamp_t);

cloudabi_errno_t cloudabi_poll_create(cloudabi_fd_t *fd);
bool cloudabi_is_poll(struct file *);

/*
 * Polling.
 */

struct cloudabi_poll_copyops {
	cloudabi_errno_t (*copyin)(const void __user *base, size_t idx,
	                           cloudabi_subscription_t *out);
	cloudabi_errno_t (*copyout)(const cloudabi_event_t *in,
	                            void __user *base, size_t idx);
};

cloudabi_errno_t cloudabi_sys_poll(const void __user *in, void __user *out,
    size_t nsubscriptions, size_t *nevents,
    const struct cloudabi_poll_copyops *copyops);
cloudabi_errno_t cloudabi_sys_poll_fd(cloudabi_fd_t fd, const void __user *in,
    size_t nin, void __user *out, size_t nout, const void __user *timeout,
    size_t *nevents, const struct cloudabi_poll_copyops *copyops);

#endif
