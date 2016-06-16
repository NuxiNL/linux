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
#include <linux/time.h>
#include <linux/timekeeping.h>

#include "cloudabi_syscalls.h"
#include "cloudabi_types_common.h"
#include "cloudabi_util.h"

/* Converts a CloudABI clock ID to a Linux clock ID. */
cloudabi_errno_t cloudabi_convert_clockid(cloudabi_clockid_t in, clockid_t *out)
{
	/* TODO(ed): Add support for CLOCK_*_CPUTIME_ID. */
	switch (in) {
	case CLOUDABI_CLOCK_MONOTONIC:
		*out = CLOCK_MONOTONIC;
		return 0;
	case CLOUDABI_CLOCK_REALTIME:
		*out = CLOCK_REALTIME;
		return 0;
	default:
		return CLOUDABI_EINVAL;
	}
}

/* Converts a struct timespec to a CloudABI timestamp. */
static int convert_timespec_to_timestamp(const struct timespec *in,
    cloudabi_timestamp_t *out)
{
	cloudabi_timestamp_t s, ns;

	/* Timestamps from before the Epoch cannot be expressed. */
	if (in->tv_sec < 0)
		return -EOVERFLOW;

	s = in->tv_sec;
	ns = in->tv_nsec;
	if (s > UINT64_MAX / NSEC_PER_SEC || (s == UINT64_MAX / NSEC_PER_SEC &&
	    ns > UINT64_MAX % NSEC_PER_SEC)) {
		/* Addition of seconds would cause an overflow. */
		return -EOVERFLOW;
	}

	*out = s * NSEC_PER_SEC + ns;
	return 0;
}

/* Fetches the time value of a clock. */
int cloudabi_clock_time_get(cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t *ret)
{
	struct timespec ts;

	/* TODO(ed): Add support for CLOCK_*_CPUTIME_ID. */
	switch (clock_id) {
	case CLOUDABI_CLOCK_MONOTONIC:
		ktime_get_ts(&ts);
		break;
	case CLOUDABI_CLOCK_REALTIME:
		ktime_get_real_ts(&ts);
		break;
	default:
		return -EINVAL;
	}
	return convert_timespec_to_timestamp(&ts, ret);
}

cloudabi_errno_t cloudabi_sys_clock_res_get(cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t *resolution)
{
	int error;
	clockid_t kclock_id;

	error = cloudabi_convert_clockid(clock_id, &kclock_id);
	if (error == 0)
		*resolution = hrtimer_resolution;
	return error;
}

cloudabi_errno_t cloudabi_sys_clock_time_get(cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t precision, cloudabi_timestamp_t *time)
{
	cloudabi_timestamp_t cts;
	int error;

	error = cloudabi_clock_time_get(clock_id, &cts);
	if (error == 0)
		*time = cts;
	return cloudabi_convert_errno(error);
}
