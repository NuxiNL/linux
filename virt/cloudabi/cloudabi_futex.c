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

#include <linux/futex.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include <asm/futex.h>
#include <asm/uaccess.h>

#include "cloudabi_syscalls.h"
#include "cloudabi_types_common.h"
#include "cloudabi_util.h"

/*
 * Futexes for CloudABI.
 *
 * On most systems, futexes are implemented as objects of a single type
 * on which a set of operations can be performed. CloudABI makes a clear
 * distinction between locks and condition variables. A lock may have
 * zero or more associated condition variables. A condition variable is
 * always associated with exactly one lock. There is a strict topology.
 * This approach has two advantages:
 *
 * - This topology is guaranteed to be acyclic. Requeueing of threads
 *   only happens in one direction (from condition variables to locks).
 *   This eases locking.
 * - It means that a futex object for a lock exists when it is unlocked,
 *   but has threads waiting on associated condition variables. Threads
 *   can be requeued to a lock even if the thread performing the wakeup
 *   does not have the lock mapped in its address space.
 *
 * This futex implementation only implements a single lock type, namely
 * a read-write lock. A regular mutex type would not be necessary, as
 * the read-write lock is as efficient as a mutex if used as such.
 * Userspace futex locks are 32 bits in size:
 *
 * - 1 bit: has threads waiting in kernel-space.
 * - 1 bit: is write-locked.
 * - 30 bits:
 *   - if write-locked: thread ID of owner.
 *   - if not write-locked: number of read locks held.
 *
 * Condition variables are also 32 bits in size. Its value is modified
 * by kernel-space exclusively. Zero indicates that it has no waiting
 * threads. Non-zero indicates the opposite.
 *
 * This implementation is optimal, in the sense that it only wakes up
 * threads if they can actually continue execution. It does not suffer
 * from the thundering herd problem. If multiple threads waiting on a
 * condition variable need to be woken up, only a single thread is
 * scheduled. All other threads are 'donated' to this thread. After the
 * thread manages to reacquire the lock, it requeues its donated threads
 * to the lock.
 *
 * TODO(ed): Store futex objects in a hash table.
 * TODO(ed): Add actual priority inheritance.
 * TODO(ed): Let futex_queue also take priorities into account.
 * TODO(ed): Make locking fine-grained.
 */

struct futex_address;
struct futex_condvar;
struct futex_lock;
struct futex_queue;
struct futex_waiter;

#define KASSERT(expr, message) BUG_ON(!(expr))

/* Wrappers around Linux list routines. */
#define	LIST_ENTRY(a)		struct list_head
#define	LIST_FOREACH		list_for_each_entry
#undef LIST_HEAD
#define	LIST_HEAD(a, b)		struct list_head
#define	LIST_HEAD_INITIALIZER(head) \
    LIST_HEAD_INIT(*(head))
#define	LIST_INSERT_HEAD(head, elm, field) \
    list_add(&(elm)->field, head)
#define	LIST_REMOVE(elm, field)	list_del(&(elm)->field)

#define	STAILQ_EMPTY		list_empty
#define	STAILQ_ENTRY(a)		struct list_head
#define	STAILQ_FOREACH		list_for_each_entry
/* TODO(ed): Hardcodes type and field! */
#define	STAILQ_FIRST(head) \
    list_first_entry(head, struct futex_waiter, fw_next)
#define	STAILQ_HEAD(a, b)	struct list_head
#define	STAILQ_INIT		INIT_LIST_HEAD
#define	STAILQ_INSERT_TAIL(head, elm, field) \
    list_add_tail(&(elm)->field, head)
#define	STAILQ_REMOVE(head, elm, type, field) \
	list_del(&(elm)->field)
#define	STAILQ_REMOVE_HEAD(head, field) \
    list_del((head)->next)

/* Identifier of a location in memory. */
struct futex_address {
	union futex_key			fa_key;
};

/* A set of waiting threads. */
struct futex_queue {
	STAILQ_HEAD(, futex_waiter)	fq_list;
	unsigned int			fq_count;
};

/* Condition variables. */
struct futex_condvar {
	/* Address of the condition variable. */
	struct futex_address		fc_address;

	/* The lock the waiters should be moved to when signalled. */
	struct futex_lock *		fc_lock;

	/* Threads waiting on the condition variable. */
	struct futex_queue		fc_waiters;
	/*
	 * Number of threads blocked on this condition variable, or
	 * being blocked on the lock after being requeued.
	 */
	unsigned int			fc_waitcount;

	/* Global list pointers. */
	LIST_ENTRY(futex_condvar)	fc_next;
};

/* Read-write locks. */
struct futex_lock {
	/* Address of the lock. */
	struct futex_address		fl_address;

	/*
	 * Current owner of the lock. LOCK_UNMANAGED if the lock is
	 * currently not owned by the kernel. LOCK_OWNER_UNKNOWN in case
	 * the owner is not known (e.g., when the lock is read-locked).
	 */
	cloudabi_tid_t			fl_owner;
#define LOCK_UNMANAGED 0x0
#define LOCK_OWNER_UNKNOWN 0x1

	/* Writers blocked on the lock. */
	struct futex_queue		fl_writers;
	/* Readers blocked on the lock. */
	struct futex_queue		fl_readers;
	/* Number of threads blocked on this lock + condition variables. */
	unsigned int			fl_waitcount;

	/* Global list pointers. */
	LIST_ENTRY(futex_lock)		fl_next;
};

/* Information associated with a thread blocked on an object. */
struct futex_waiter {
	/* Thread ID. */
	cloudabi_tid_t			fw_tid;
	/* Condition variable used for waiting. */
	wait_queue_head_t		fw_wait;

	/* Queue this waiter is currently placed in. */
	struct futex_queue *		fw_queue;
	/* List pointers of fw_queue. */
	STAILQ_ENTRY(futex_waiter)	fw_next;

	/* Lock has been acquired. */
	bool				fw_locked;
	/* If not locked, threads that should block after acquiring. */
	struct futex_queue		fw_donated;
};

/* Global data structures. */
static DEFINE_MUTEX(futex_global_lock);

static LIST_HEAD(, futex_lock) futex_lock_list =
    LIST_HEAD_INITIALIZER(&futex_lock_list);
static LIST_HEAD(, futex_condvar) futex_condvar_list =
    LIST_HEAD_INITIALIZER(&futex_condvar_list);

/* Utility functions. */
static void futex_lock_assert(const struct futex_lock *);
static struct futex_lock *futex_lock_lookup_locked(struct futex_address *);
static void futex_lock_release(struct futex_lock *);
static int futex_lock_tryrdlock(struct futex_lock *, cloudabi_lock_t *);
static int futex_lock_unmanage(struct futex_lock *, cloudabi_lock_t *);
static int futex_lock_update_owner(struct futex_lock *, cloudabi_lock_t *);
static int futex_lock_wake_up_next(struct futex_lock *, cloudabi_lock_t *);
static unsigned int futex_queue_count(const struct futex_queue *);
static void futex_queue_init(struct futex_queue *);
static void futex_queue_requeue(struct futex_queue *, struct futex_queue *,
    unsigned int);
static int futex_queue_sleep(struct futex_queue *, struct futex_lock *,
    struct futex_waiter *, struct task_struct *, cloudabi_clockid_t,
    cloudabi_timestamp_t, cloudabi_timestamp_t);
static cloudabi_tid_t futex_queue_tid_best(const struct futex_queue *);
static void futex_queue_wake_up_all(struct futex_queue *);
static void futex_queue_wake_up_best(struct futex_queue *);
static void futex_queue_wake_up_donate(struct futex_queue *, unsigned int);
static int futex_user_load(uint32_t *, uint32_t *);
static int futex_user_store(uint32_t *, uint32_t);
static int futex_user_cmpxchg(uint32_t *, uint32_t, uint32_t *, uint32_t);

static int cloudabi_futex_condvar_wait_unlocked(struct futex_condvar *,
    struct futex_waiter *, struct task_struct *, cloudabi_condvar_t *,
    cloudabi_clockid_t, cloudabi_timestamp_t, cloudabi_timestamp_t);

/*
 * futex_address operations.
 */

static int
futex_address_create(struct futex_address *fa, struct task_struct *td,
    const void *object, cloudabi_scope_t scope)
{
	switch (scope) {
	case CLOUDABI_SCOPE_PRIVATE:
		return get_futex_key(object, 0, &fa->fa_key, VERIFY_WRITE);
	case CLOUDABI_SCOPE_SHARED:
		return get_futex_key(object, FLAGS_SHARED, &fa->fa_key,
		                     VERIFY_WRITE);
	default:
		return -EINVAL;
	}
}

static void
futex_address_free(struct futex_address *fa)
{
	put_futex_key(&fa->fa_key);
}

static bool
futex_address_match(const struct futex_address *fa1,
    const struct futex_address *fa2)
{
	return match_futex(&fa1->fa_key, &fa2->fa_key);
}

/*
 * futex_condvar operations.
 */

static void
futex_condvar_assert(const struct futex_condvar *fc)
{

	KASSERT(fc->fc_waitcount >= futex_queue_count(&fc->fc_waiters),
	    ("Total number of waiters cannot be smaller than the wait queue"));
	futex_lock_assert(fc->fc_lock);
}

static int
futex_condvar_lookup(struct task_struct *td, const cloudabi_condvar_t *address,
    cloudabi_scope_t scope, struct futex_condvar **fcret)
{
	struct futex_address fa_condvar;
	struct futex_condvar *fc;
	int error;

	error = futex_address_create(&fa_condvar, td, address, scope);
	if (error != 0)
		return (error);

	mutex_lock(&futex_global_lock);
	LIST_FOREACH(fc, &futex_condvar_list, fc_next) {
		if (futex_address_match(&fc->fc_address, &fa_condvar)) {
			/* Found matching lock object. */
			futex_address_free(&fa_condvar);
			futex_condvar_assert(fc);
			*fcret = fc;
			return (0);
		}
	}
	mutex_unlock(&futex_global_lock);
	futex_address_free(&fa_condvar);
	return (-ENOENT);
}

static int
futex_condvar_lookup_or_create(struct task_struct *td,
    const cloudabi_condvar_t *condvar, cloudabi_scope_t condvar_scope,
    const cloudabi_lock_t *lock, cloudabi_scope_t lock_scope,
    struct futex_condvar **fcret)
{
	struct futex_address fa_condvar, fa_lock;
	struct futex_condvar *fc;
	struct futex_lock *fl;
	int error;

	error = futex_address_create(&fa_condvar, td, condvar, condvar_scope);
	if (error != 0)
		return (error);
	error = futex_address_create(&fa_lock, td, lock, lock_scope);
	if (error != 0) {
		futex_address_free(&fa_condvar);
		return (error);
	}

	mutex_lock(&futex_global_lock);
	LIST_FOREACH(fc, &futex_condvar_list, fc_next) {
		if (!futex_address_match(&fc->fc_address, &fa_condvar))
			continue;
		fl = fc->fc_lock;
		if (!futex_address_match(&fl->fl_address, &fa_lock)) {
			/* Condition variable is owned by a different lock. */
			futex_address_free(&fa_condvar);
			futex_address_free(&fa_lock);
			mutex_unlock(&futex_global_lock);
			return (-EINVAL);
		}

		/* Found fully matching condition variable. */
		futex_address_free(&fa_condvar);
		futex_address_free(&fa_lock);
		futex_condvar_assert(fc);
		*fcret = fc;
		return (0);
	}

	/* None found. Create new condition variable object. */
	fc = kmalloc(sizeof(*fc), GFP_KERNEL | __GFP_NOFAIL);
	fc->fc_address = fa_condvar;
	fc->fc_lock = futex_lock_lookup_locked(&fa_lock);
	futex_queue_init(&fc->fc_waiters);
	fc->fc_waitcount = 0;
	LIST_INSERT_HEAD(&futex_condvar_list, fc, fc_next);
	*fcret = fc;
	return (0);
}

static void
futex_condvar_release(struct futex_condvar *fc)
{
	struct futex_lock *fl;

	futex_condvar_assert(fc);
	fl = fc->fc_lock;
	if (fc->fc_waitcount == 0) {
		/* Condition variable has no waiters. Deallocate it. */
		futex_address_free(&fc->fc_address);
		LIST_REMOVE(fc, fc_next);
		kfree(fc);
	}
	futex_lock_release(fl);
}

static int
futex_condvar_unmanage(struct futex_condvar *fc,
    cloudabi_condvar_t *condvar)
{

	if (futex_queue_count(&fc->fc_waiters) != 0)
		return (0);
	return (futex_user_store(condvar, CLOUDABI_CONDVAR_HAS_NO_WAITERS));
}

/*
 * futex_lock operations.
 */

static void
futex_lock_assert(const struct futex_lock *fl)
{

	/*
	 * A futex lock can only be kernel-managed if it has waiters.
	 * Vice versa: if a futex lock has waiters, it must be
	 * kernel-managed.
	 */
	KASSERT((fl->fl_owner == LOCK_UNMANAGED) ==
	    (futex_queue_count(&fl->fl_readers) == 0 &&
	    futex_queue_count(&fl->fl_writers) == 0),
	    ("Managed locks must have waiting threads"));
	KASSERT(fl->fl_waitcount != 0 || fl->fl_owner == LOCK_UNMANAGED,
	    ("Lock with no waiters must be unmanaged"));
}

static int
futex_lock_lookup(struct task_struct *td, const cloudabi_lock_t *address,
    cloudabi_scope_t scope, struct futex_lock **flret)
{
	struct futex_address fa;
	int error;

	error = futex_address_create(&fa, td, address, scope);
	if (error != 0)
		return (error);

	mutex_lock(&futex_global_lock);
	*flret = futex_lock_lookup_locked(&fa);
	return (0);
}

static struct futex_lock *
futex_lock_lookup_locked(struct futex_address *fa)
{
	struct futex_lock *fl;

	LIST_FOREACH(fl, &futex_lock_list, fl_next) {
		if (futex_address_match(&fl->fl_address, fa)) {
			/* Found matching lock object. */
			futex_address_free(fa);
			futex_lock_assert(fl);
			return (fl);
		}
	}

	/* None found. Create new lock object. */
	fl = kmalloc(sizeof(*fl), GFP_KERNEL | __GFP_NOFAIL);
	fl->fl_address = *fa;
	fl->fl_owner = LOCK_UNMANAGED;
	futex_queue_init(&fl->fl_readers);
	futex_queue_init(&fl->fl_writers);
	fl->fl_waitcount = 0;
	LIST_INSERT_HEAD(&futex_lock_list, fl, fl_next);
	return (fl);
}

static int
futex_lock_rdlock(struct futex_lock *fl, struct task_struct *td,
    cloudabi_lock_t *lock, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	struct futex_waiter fw;
	int error;

	error = futex_lock_tryrdlock(fl, lock);
	if (error == -EBUSY) {
		/* Suspend execution. */
		KASSERT(fl->fl_owner != LOCK_UNMANAGED,
		    ("Attempted to sleep on an unmanaged lock"));
		error = futex_queue_sleep(&fl->fl_readers, fl, &fw, td,
		    clock_id, timeout, precision);
		KASSERT((error == 0) == fw.fw_locked,
		    ("Should have locked write lock on success"));
		KASSERT(futex_queue_count(&fw.fw_donated) == 0,
		    ("Lock functions cannot receive threads"));
	}
	if (error != 0)
		futex_lock_unmanage(fl, lock);
	return (error);
}

static void
futex_lock_release(struct futex_lock *fl)
{

	futex_lock_assert(fl);
	if (fl->fl_waitcount == 0) {
		/* Lock object is unreferenced. Deallocate it. */
		KASSERT(fl->fl_owner == LOCK_UNMANAGED,
		    ("Attempted to free a managed lock"));
		futex_address_free(&fl->fl_address);
		LIST_REMOVE(fl, fl_next);
		kfree(fl);
	}
	mutex_unlock(&futex_global_lock);
}

static int
futex_lock_unmanage(struct futex_lock *fl, cloudabi_lock_t *lock)
{
	cloudabi_lock_t cmp, old;
	int error;

	if (futex_queue_count(&fl->fl_readers) == 0 &&
	    futex_queue_count(&fl->fl_writers) == 0) {
		/* Lock should be unmanaged. */
		fl->fl_owner = LOCK_UNMANAGED;

		/* Clear kernel-managed bit. */
		error = futex_user_load(lock, &old);
		if (error != 0)
			return (error);
		for (;;) {
			cmp = old;
			error = futex_user_cmpxchg(lock, cmp, &old,
			    cmp & ~CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return (error);
			if (old == cmp)
				break;
		}
	}
	return (0);
}

/* Sets an owner of a lock, based on a userspace lock value. */
static void
futex_lock_set_owner(struct futex_lock *fl, cloudabi_lock_t lock)
{

	/* Lock has no explicit owner. */
	if ((lock & ~CLOUDABI_LOCK_WRLOCKED) == 0) {
		fl->fl_owner = LOCK_OWNER_UNKNOWN;
		return;
	}
	lock &= ~(CLOUDABI_LOCK_WRLOCKED | CLOUDABI_LOCK_KERNEL_MANAGED);

	/* Don't allow userspace to silently unlock. */
	if (lock == LOCK_UNMANAGED) {
		fl->fl_owner = LOCK_OWNER_UNKNOWN;
		return;
	}
	fl->fl_owner = lock;
}

static int
futex_lock_unlock(struct futex_lock *fl, struct task_struct *td,
    cloudabi_lock_t *lock)
{
	int error;

	/* Validate that this thread is allowed to unlock. */
	error = futex_lock_update_owner(fl, lock);
	if (error != 0)
		return (error);
	if (fl->fl_owner != LOCK_UNMANAGED &&
	    fl->fl_owner != cloudabi_gettid(td))
		return (-EPERM);
	return (futex_lock_wake_up_next(fl, lock));
}

/* Syncs in the owner of the lock from userspace if needed. */
static int
futex_lock_update_owner(struct futex_lock *fl, cloudabi_lock_t *address)
{
	cloudabi_lock_t lock;
	int error;

	if (fl->fl_owner == LOCK_OWNER_UNKNOWN) {
		error = futex_user_load(address, &lock);
		if (error != 0)
			return (error);
		futex_lock_set_owner(fl, lock);
	}
	return (0);
}

static int
futex_lock_tryrdlock(struct futex_lock *fl, cloudabi_lock_t *address)
{
	cloudabi_lock_t old, cmp;
	int error;

	if (fl->fl_owner != LOCK_UNMANAGED) {
		/* Lock is already acquired. */
		return (-EBUSY);
	}

	old = CLOUDABI_LOCK_UNLOCKED;
	for (;;) {
		if ((old & CLOUDABI_LOCK_KERNEL_MANAGED) != 0) {
			/*
			 * Userspace lock is kernel-managed, even though
			 * the kernel disagrees.
			 */
			return (-EINVAL);
		}

		if ((old & CLOUDABI_LOCK_WRLOCKED) == 0) {
			/*
			 * Lock is not write-locked. Attempt to acquire
			 * it by increasing the read count.
			 */
			cmp = old;
			error = futex_user_cmpxchg(address, cmp, &old, cmp + 1);
			if (error != 0)
				return (error);
			if (old == cmp) {
				/* Success. */
				return (0);
			}
		} else {
			/* Lock is write-locked. Make it kernel-managed. */
			cmp = old;
			error = futex_user_cmpxchg(address, cmp, &old,
			    cmp | CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return (error);
			if (old == cmp) {
				/* Success. */
				futex_lock_set_owner(fl, cmp);
				return (-EBUSY);
			}
		}
	}
}

static int
futex_lock_trywrlock(struct futex_lock *fl, cloudabi_lock_t *address,
    cloudabi_tid_t tid, bool force_kernel_managed)
{
	cloudabi_lock_t old, new, cmp;
	int error;

	if (fl->fl_owner == tid) {
		/* Attempted to acquire lock recursively. */
		return (-EDEADLK);
	}
	if (fl->fl_owner != LOCK_UNMANAGED) {
		/* Lock is already acquired. */
		return (-EBUSY);
	}

	old = CLOUDABI_LOCK_UNLOCKED;
	for (;;) {
		if ((old & CLOUDABI_LOCK_KERNEL_MANAGED) != 0) {
			/*
			 * Userspace lock is kernel-managed, even though
			 * the kernel disagrees.
			 */
			return (-EINVAL);
		}
		if (old == (tid | CLOUDABI_LOCK_WRLOCKED)) {
			/* Attempted to acquire lock recursively. */
			return (-EDEADLK);
		}

		if (old == CLOUDABI_LOCK_UNLOCKED) {
			/* Lock is unlocked. Attempt to acquire it. */
			new = tid | CLOUDABI_LOCK_WRLOCKED;
			if (force_kernel_managed)
				new |= CLOUDABI_LOCK_KERNEL_MANAGED;
			error = futex_user_cmpxchg(address,
			    CLOUDABI_LOCK_UNLOCKED, &old, new);
			if (error != 0)
				return (error);
			if (old == CLOUDABI_LOCK_UNLOCKED) {
				/* Success. */
				if (force_kernel_managed)
					fl->fl_owner = tid;
				return (0);
			}
		} else {
			/* Lock is still locked. Make it kernel-managed. */
			cmp = old;
			error = futex_user_cmpxchg(address, cmp, &old,
			    cmp | CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return (error);
			if (old == cmp) {
				/* Success. */
				futex_lock_set_owner(fl, cmp);
				return (-EBUSY);
			}
		}
	}
}

static int
futex_lock_wake_up_next(struct futex_lock *fl, cloudabi_lock_t *lock)
{
	cloudabi_tid_t tid;
	int error;

	/*
	 * Determine which thread(s) to wake up. Prefer waking up
	 * writers over readers to prevent write starvation.
	 */
	if (futex_queue_count(&fl->fl_writers) > 0) {
		/* Transfer ownership to a single write-locker. */
		if (futex_queue_count(&fl->fl_writers) > 1 ||
		    futex_queue_count(&fl->fl_readers) > 0) {
			/* Lock should remain managed afterwards. */
			tid = futex_queue_tid_best(&fl->fl_writers);
			error = futex_user_store(lock,
			    tid | CLOUDABI_LOCK_WRLOCKED |
			    CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return (error);

			futex_queue_wake_up_best(&fl->fl_writers);
			fl->fl_owner = tid;
		} else {
			/* Lock can become unmanaged afterwards. */
			error = futex_user_store(lock,
			    futex_queue_tid_best(&fl->fl_writers) |
			    CLOUDABI_LOCK_WRLOCKED);
			if (error != 0)
				return (error);

			futex_queue_wake_up_best(&fl->fl_writers);
			fl->fl_owner = LOCK_UNMANAGED;
		}
	} else {
		/* Transfer ownership to all read-lockers (if any). */
		error = futex_user_store(lock,
		    futex_queue_count(&fl->fl_readers));
		if (error != 0)
			return (error);

		/* Wake up all threads. */
		futex_queue_wake_up_all(&fl->fl_readers);
		fl->fl_owner = LOCK_UNMANAGED;
	}
	return (0);
}

static int
futex_lock_wrlock(struct futex_lock *fl, struct task_struct *td,
    cloudabi_lock_t *lock, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision,
    struct futex_queue *donated)
{
	struct futex_waiter fw;
	int error;

	error = futex_lock_trywrlock(fl, lock, cloudabi_gettid(td),
	    futex_queue_count(donated) > 0);

	if (error == 0 || error == -EBUSY) {
		/* Put donated threads in queue before suspending. */
		KASSERT(futex_queue_count(donated) == 0 ||
		    fl->fl_owner != LOCK_UNMANAGED,
		    ("Lock should be managed if we are going to donate"));
		futex_queue_requeue(donated, &fl->fl_writers, UINT_MAX);
	} else {
		/*
		 * This thread cannot deal with the donated threads.
		 * Wake up the next thread and let it try it by itself.
		 */
		futex_queue_wake_up_donate(donated, UINT_MAX);
	}

	if (error == -EBUSY) {
		/* Suspend execution if the lock was busy. */
		KASSERT(fl->fl_owner != LOCK_UNMANAGED,
		    ("Attempted to sleep on an unmanaged lock"));
		error = futex_queue_sleep(&fl->fl_writers, fl, &fw, td,
		    clock_id, timeout, precision);
		KASSERT((error == 0) == fw.fw_locked,
		    ("Should have locked write lock on success"));
		KASSERT(futex_queue_count(&fw.fw_donated) == 0,
		    ("Lock functions cannot receive threads"));
	}
	if (error != 0)
		futex_lock_unmanage(fl, lock);
	return (error);
}

/*
 * futex_queue operations.
 */

static cloudabi_tid_t
futex_queue_tid_best(const struct futex_queue *fq)
{

	return (STAILQ_FIRST(&fq->fq_list)->fw_tid);
}

static unsigned int
futex_queue_count(const struct futex_queue *fq)
{

	return (fq->fq_count);
}

static void
futex_queue_init(struct futex_queue *fq)
{

	STAILQ_INIT(&fq->fq_list);
	fq->fq_count = 0;
}

static int
futex_queue_wait(wait_queue_head_t *q)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(q, &wait, TASK_INTERRUPTIBLE);
	mutex_unlock(&futex_global_lock);
	schedule();
	mutex_lock(&futex_global_lock);
	finish_wait(q, &wait);
	if (signal_pending(current))
		return (-ERESTARTSYS);
	return (0);
}

static int
futex_queue_timedwait(wait_queue_head_t *q, unsigned long jiffies)
{
	DEFINE_WAIT(wait);
	long ret;

	prepare_to_wait(q, &wait, TASK_INTERRUPTIBLE);
	mutex_unlock(&futex_global_lock);
	ret = schedule_timeout(jiffies);
	mutex_lock(&futex_global_lock);
	finish_wait(q, &wait);
	if (signal_pending(current))
		return (-ERESTARTSYS);
	if (ret == 0)
		return (-ETIMEDOUT);
	return (0);
}

static int
futex_queue_sleep(struct futex_queue *fq, struct futex_lock *fl,
    struct futex_waiter *fw, struct task_struct *td,
    cloudabi_clockid_t clock_id, cloudabi_timestamp_t timeout,
    cloudabi_timestamp_t precision)
{
	struct timespec ts;
	cloudabi_timestamp_t now;
	unsigned long jiffies;
	int error;

	/* Initialize futex_waiter object. */
	fw->fw_tid = cloudabi_gettid(td);
	fw->fw_locked = false;
	futex_queue_init(&fw->fw_donated);

	/* Place object in the queue. */
	fw->fw_queue = fq;
	STAILQ_INSERT_TAIL(&fq->fq_list, fw, fw_next);
	++fq->fq_count;

	init_waitqueue_head(&fw->fw_wait);
	++fl->fl_waitcount;

	/* Wait respecting the timeout. */
	futex_lock_assert(fl);
	do {
		/* Fetch current time. */
		error = cloudabi_clock_time_get(clock_id, &now);
		if (error != 0)
			break;
		if (now >= timeout) {
			error = -ETIMEDOUT;
			break;
		}

		/* Convert to jiffies. */
		ts.tv_sec = (timeout - now) / 1000000000;
		ts.tv_nsec = (timeout - now) % 1000000000;
		jiffies = timespec_to_jiffies(&ts);

		/* Wait. */
		error = futex_queue_timedwait(&fw->fw_wait, jiffies);
		if (error != 0)
			break;
	} while (fw->fw_queue == fq);
	futex_lock_assert(fl);
	if ((error == 0 || error == -ETIMEDOUT) &&
	    fw->fw_queue != NULL && fw->fw_queue != fq) {
		/*
		 * We got signalled, but observed a timeout while
		 * waiting to reacquire the lock. In other words, we
		 * didn't actually time out. Go back to sleep and wait
		 * for the lock to be reacquired.
		 */
		do {
			error = futex_queue_wait(&fw->fw_wait);
		} while (error == 0 && fw->fw_queue != NULL);
		futex_lock_assert(fl);
	}

	--fl->fl_waitcount;

	fq = fw->fw_queue;
	if (fq == NULL) {
		/* Thread got dequeued, so we've slept successfully. */
		return (0);
	}

	/* Thread is still enqueued. Remove it. */
	KASSERT(error != 0, ("Woken up thread is still enqueued"));
	STAILQ_REMOVE(&fq->fq_list, fw, futex_waiter, fw_next);
	--fq->fq_count;
	return (error);
}

/* Moves up to nwaiters waiters from one queue to another. */
static void
futex_queue_requeue(struct futex_queue *fqfrom, struct futex_queue *fqto,
    unsigned int nwaiters)
{
	struct futex_waiter *fw;

	/* Move waiters to the target queue. */
	while (nwaiters-- > 0 && !STAILQ_EMPTY(&fqfrom->fq_list)) {
		fw = STAILQ_FIRST(&fqfrom->fq_list);
		STAILQ_REMOVE_HEAD(&fqfrom->fq_list, fw_next);
		--fqfrom->fq_count;

		fw->fw_queue = fqto;
		STAILQ_INSERT_TAIL(&fqto->fq_list, fw, fw_next);
		++fqto->fq_count;
	}
}

/* Wakes up all waiters in a queue. */
static void
futex_queue_wake_up_all(struct futex_queue *fq)
{
	struct futex_waiter *fw;

	STAILQ_FOREACH(fw, &fq->fq_list, fw_next) {
		fw->fw_locked = true;
		fw->fw_queue = NULL;
		wake_up(&fw->fw_wait);
	}

	STAILQ_INIT(&fq->fq_list);
	fq->fq_count = 0;
}

/*
 * Wakes up the best waiter (i.e., the waiter having the highest
 * priority) in a queue.
 */
static void
futex_queue_wake_up_best(struct futex_queue *fq)
{
	struct futex_waiter *fw;

	fw = STAILQ_FIRST(&fq->fq_list);
	fw->fw_locked = true;
	fw->fw_queue = NULL;
	wake_up(&fw->fw_wait);

	STAILQ_REMOVE_HEAD(&fq->fq_list, fw_next);
	--fq->fq_count;
}

static void
futex_queue_wake_up_donate(struct futex_queue *fq, unsigned int nwaiters)
{
	struct futex_waiter *fw;

	fw = STAILQ_FIRST(&fq->fq_list);
	if (fw == NULL)
		return;
	fw->fw_locked = false;
	fw->fw_queue = NULL;
	wake_up(&fw->fw_wait);

	STAILQ_REMOVE_HEAD(&fq->fq_list, fw_next);
	--fq->fq_count;
	futex_queue_requeue(fq, &fw->fw_donated, nwaiters);
}

/*
 * futex_user operations. Used to adjust values in userspace.
 */

static int
futex_user_load(uint32_t __user *obj, uint32_t *val)
{
	int error;

	error = __copy_from_user_inatomic(val, obj, sizeof(*obj));
	return error != 0 ? -EFAULT : 0;
}

static int
futex_user_store(uint32_t __user *obj, uint32_t val)
{
	int error;

	error = __copy_to_user_inatomic(obj, &val, sizeof(*obj));
	return error != 0 ? -EFAULT : 0;
}

static int
futex_user_cmpxchg(uint32_t __user *obj, uint32_t cmp, uint32_t *old,
    uint32_t new)
{
	return futex_atomic_cmpxchg_inatomic(old, obj, cmp, new);
}

/*
 * Blocking calls: acquiring locks, waiting on condition variables.
 */

int
cloudabi_futex_condvar_wait(struct task_struct *td, cloudabi_condvar_t *condvar,
    cloudabi_scope_t condvar_scope, cloudabi_lock_t *lock,
    cloudabi_scope_t lock_scope, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	struct futex_condvar *fc;
	struct futex_lock *fl;
	struct futex_waiter fw;
	int error, error2;

	/* Lookup condition variable object. */
	error = futex_condvar_lookup_or_create(td, condvar, condvar_scope, lock,
	    lock_scope, &fc);
	if (error != 0)
		return (error);
	fl = fc->fc_lock;

	/*
	 * Set the condition variable to something other than
	 * CLOUDABI_CONDVAR_HAS_NO_WAITERS to make userspace threads
	 * call into the kernel to perform wakeups.
	 */
	error = futex_user_store(condvar, ~CLOUDABI_CONDVAR_HAS_NO_WAITERS);
	if (error != 0) {
		futex_condvar_release(fc);
		return (error);
	}

	/* Drop the lock. */
	error = futex_lock_unlock(fl, td, lock);
	if (error != 0) {
		futex_condvar_unmanage(fc, condvar);
		futex_condvar_release(fc);
		return (error);
	}

	++fc->fc_waitcount;
	error = cloudabi_futex_condvar_wait_unlocked(fc, &fw, td, condvar,
	    clock_id, timeout, precision);
	if (fw.fw_locked) {
		/* Waited and got the lock assigned to us. */
		KASSERT(futex_queue_count(&fw.fw_donated) == 0,
		    ("Received threads while being locked"));
	} else if (error == 0 || error == -ETIMEDOUT) {
		if (error != 0)
			futex_condvar_unmanage(fc, condvar);
		/*
		 * Got woken up without having the lock assigned to us.
		 * This can happen in two cases:
		 *
		 * 1. We observed a timeout on a condition variable.
		 * 2. We got signalled on a condition variable while the
		 *    associated lock is unlocked. We are the first
		 *    thread that gets woken up. This thread is
		 *    responsible for reacquiring the userspace lock.
		 */
		error2 = futex_lock_wrlock(fl, td, lock,
		    CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0, &fw.fw_donated);
		if (error2 != 0)
			error = error2;
	} else {
		KASSERT(futex_queue_count(&fw.fw_donated) == 0,
		    ("Received threads on error"));
		futex_condvar_unmanage(fc, condvar);
		futex_lock_unmanage(fl, lock);
	}
	--fc->fc_waitcount;
	futex_condvar_release(fc);
	return (error);
}

static int
cloudabi_futex_condvar_wait_unlocked(struct futex_condvar *fc,
    struct futex_waiter *fw, struct task_struct *td,
    cloudabi_condvar_t *condvar, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	int error;

	fw->fw_locked = false;
	futex_queue_init(&fw->fw_donated);

	/*
	 * Set the condition variable to something other than
	 * CLOUDABI_CONDVAR_HAS_NO_WAITERS to make userspace threads
	 * call into the kernel to perform wakeups.
	 */
	error = futex_user_store(condvar, ~CLOUDABI_CONDVAR_HAS_NO_WAITERS);
	if (error != 0)
		return (error);

	error = futex_queue_sleep(&fc->fc_waiters, fc->fc_lock, fw, td,
	    clock_id, timeout, precision);
	return (error);
}

int
cloudabi_futex_lock_rdlock(struct task_struct *td, cloudabi_lock_t *lock,
    cloudabi_scope_t scope, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	struct futex_lock *fl;
	int error;

	/* Look up lock object. */
	error = futex_lock_lookup(td, lock, scope, &fl);
	if (error != 0)
		return (error);

	error = futex_lock_rdlock(fl, td, lock, clock_id, timeout,
	    precision);
	futex_lock_release(fl);
	return (error);
}

int
cloudabi_futex_lock_wrlock(struct task_struct *td, cloudabi_lock_t *lock,
    cloudabi_scope_t scope, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	struct futex_lock *fl;
	struct futex_queue fq;
	int error;

	/* Look up lock object. */
	error = futex_lock_lookup(td, lock, scope, &fl);
	if (error != 0)
		return (error);

	futex_queue_init(&fq);
	error = futex_lock_wrlock(fl, td, lock, clock_id, timeout,
	    precision, &fq);
	futex_lock_release(fl);
	return (error);
}

/*
 * Non-blocking calls: releasing locks, signalling condition variables.
 */

cloudabi_errno_t cloudabi_sys_condvar_signal(cloudabi_condvar_t __user *condvar,
    cloudabi_scope_t scope, cloudabi_nthreads_t nwaiters)
{
	struct futex_condvar *fc;
	struct futex_lock *fl;
	struct task_struct *td;
	int error;

	if (nwaiters == 0) {
		/* No threads to wake up. */
		return (0);
	}

	/* Look up futex object. */
	td = current;
	error = futex_condvar_lookup(td, condvar, scope, &fc);
	if (error != 0) {
		/* Race condition: condition variable with no waiters. */
		if (error == -ENOENT)
			return (0);
		return (cloudabi_convert_errno(error));
	}
	fl = fc->fc_lock;

	if (fl->fl_owner == LOCK_UNMANAGED) {
		/*
		 * The lock is currently not managed by the kernel,
		 * meaning we must attempt to acquire the userspace lock
		 * first. We cannot requeue threads to an unmanaged lock,
		 * as these threads will then never be scheduled.
		 *
		 * Unfortunately, the memory address of the lock is
		 * unknown from this context, meaning that we cannot
		 * acquire the lock on behalf of the first thread to be
		 * scheduled. The lock may even not be mapped within the
		 * address space of the current thread.
		 *
		 * To solve this, wake up a single waiter that will
		 * attempt to acquire the lock. Donate all of the other
		 * waiters that need to be woken up to this waiter, so
		 * it can requeue them after acquiring the lock.
		 */
		futex_queue_wake_up_donate(&fc->fc_waiters, nwaiters - 1);
	} else {
		/*
		 * Lock is already managed by the kernel. This makes it
		 * easy, as we can requeue the threads from the
		 * condition variable directly to the associated lock.
		 */
		futex_queue_requeue(&fc->fc_waiters, &fl->fl_writers, nwaiters);
	}

	/* Clear userspace condition variable if all waiters are gone. */
	error = futex_condvar_unmanage(fc, condvar);
	futex_condvar_release(fc);
	return (cloudabi_convert_errno(error));
}

cloudabi_errno_t cloudabi_sys_lock_unlock(cloudabi_lock_t __user *lock,
    cloudabi_scope_t scope)
{
	struct futex_lock *fl;
	struct task_struct *td;
	int error;

	td = current;
	error = futex_lock_lookup(td, lock, scope, &fl);
	if (error != 0)
		return (cloudabi_convert_errno(error));
	error = futex_lock_unlock(fl, td, lock);
	futex_lock_release(fl);
	return (cloudabi_convert_errno(error));
}
