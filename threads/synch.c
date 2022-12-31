/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

   /* Copyright (c) 1992-1996 The Regents of the University of California.
	  All rights reserved.

	  Permission to use, copy, modify, and distribute this software
	  and its documentation for any purpose, without fee, and
	  without written agreement is hereby granted, provided that the
	  above copyright notice and the following two paragraphs appear
	  in all copies of this software.

	  IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
	  ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
	  CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
	  AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
	  HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	  THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
	  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
	  PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
	  BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
	  PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
	  MODIFICATIONS.
	  */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define PRI_DONATE_MAX_DEPTH 8 /* for priority nest */

	  /* Initializes semaphore SEMA to VALUE.  A semaphore is a
		 nonnegative integer along with two atomic operators for
		 manipulating it:

		 - down or "P": wait for the value to become positive, then
		 decrement it.

		 - up or "V": increment the value (and wake up one waiting
		 thread, if any). */

void
sema_init(struct semaphore *sema, unsigned value) {
	ASSERT(sema != NULL);

	sema->value = value;
	list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down(struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT(sema != NULL);
	ASSERT(!intr_context());

	old_level = intr_disable();
	while (sema->value == 0) {  // in lock's aspect, if sema -> value == 1, it means there is no thread that has lock, so pass this statement
		list_push_back(&sema->waiters, &thread_current()->elem);
		thread_block();
	}
	sema->value--;
	intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down(struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level(old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
static bool
thread_priority_greater(const struct list_elem *lhs, const struct list_elem *rhs, void *aux UNUSED) {
	return list_entry(lhs, struct thread, elem)->priority > list_entry(rhs, struct thread, elem)->priority;
} //left, right
void
sema_up(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);

	old_level = intr_disable();

	if (!list_empty(&sema->waiters)) {
		// since the compare function is "greater", if use list_min, can find thread that has highest priority
		struct list_elem *e = list_min(&sema->waiters, thread_priority_greater, NULL);
		struct thread *t = list_entry(e, struct thread, elem);
		list_remove(e);
		thread_unblock(t);
	}
	sema->value++;

	if (intr_context()) {
		intr_yield_on_return();
	}
	else {
		thread_yield();
	}
	intr_set_level(old_level);

}


static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test(void) {
	struct semaphore sema[2];
	int i;

	printf("Testing semaphores...");
	sema_init(&sema[0], 0);
	sema_init(&sema[1], 0);
	thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up(&sema[0]);
		sema_down(&sema[1]);
	}
	printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper(void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down(&sema[0]);
		sema_up(&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init(struct lock *lock) {
	ASSERT(lock != NULL);
	lock->holder = NULL;
	lock->max_priority = PRI_MIN;
	sema_init(&lock->semaphore, 1);
}



static bool
lock_priority_greater(const struct list_elem *lhs, const struct list_elem *rhs, void *aux UNUSED) {
	return list_entry(lhs, struct lock, elem)->max_priority > list_entry(rhs, struct lock, elem)->max_priority;
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.


   This function(lock_acquire) may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if we need to sleep. */

void
lock_acquire(struct lock *lock) {
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(!lock_held_by_current_thread(lock));

	struct thread *t_cur = thread_current();

	if (lock->holder != NULL) {
		t_cur->waiting_lock = lock;
		//update lock priority and holder priority
		lock->max_priority = t_cur->priority > lock->max_priority ? t_cur->priority : lock->max_priority;

		struct thread *t_holder = lock->holder;
		t_holder->priority = t_cur->priority > t_holder->priority ? t_cur->priority : t_holder->priority;

		/* below is also possible */
		// t_holder->priority = lock->max_priority > t_holder->priority ? lock->max_priority : t_holder->priority; 

		size_t depth = 0;
		while (t_holder->waiting_lock != NULL && depth < PRI_DONATE_MAX_DEPTH) {
			struct thread *t_next = t_holder->waiting_lock->holder;
			if (t_next->priority > t_holder->priority) {
				break;
			}
			t_holder->waiting_lock->max_priority = t_holder->priority;
			t_next->priority = t_holder->priority;
			t_holder = t_next;
			depth++;
		}
	}

	sema_down(&lock->semaphore); //


	//after t_cur acquire the lock, then the holder of the lock is t_cur and t_cur has no waiting lock

	list_insert_ordered(&t_cur->lockhold_list, &lock->elem, lock_priority_greater, NULL); // insert lock elem into lockhold_list of t_cur, so that it can be used when lock released
	t_cur->waiting_lock = NULL;

	lock->holder = t_cur;
}

// void
// lock_acquire(struct lock *lock) {
// 	ASSERT(lock != NULL);
// 	ASSERT(!intr_context());
// 	ASSERT(!lock_held_by_current_thread(lock));

// 	sema_down(&lock->semaphore);
// 	lock->holder = thread_current();
// }


/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire(struct lock *lock) {
	bool success;

	ASSERT(lock != NULL);
	ASSERT(!lock_held_by_current_thread(lock));

	success = sema_try_down(&lock->semaphore);
	if (success)
		lock->holder = thread_current();
	return success;
}

/* Releases LOCK, "which must be owned by the current thread."
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release(struct lock *lock) {
	ASSERT(lock != NULL);
	ASSERT(lock_held_by_current_thread(lock)); // this condition is necessary on default

	struct thread *t_cur = thread_current(); // we will release lock owned by t_cur

	list_remove(&lock->elem); // since we use lock->elem only in lockhold list, it means removing lock from lockhold list.

	t_cur->priority = t_cur->base_priority; // restore original priority, since we used priority variable for preventing "priority inversion"

	if (!list_empty(&t_cur->lockhold_list)) {
		struct lock *lock_front = list_entry(list_front(&t_cur->lockhold_list), struct lock, elem);
		t_cur->priority = lock_front->max_priority > t_cur->priority ? lock_front->max_priority : t_cur->priority;
	}

	lock->holder = NULL;
	sema_up(&lock->semaphore);
}
// void
// lock_release(struct lock *lock) {
// 	ASSERT(lock != NULL);
// 	ASSERT(lock_held_by_current_thread(lock));

// 	lock->holder = NULL;
// 	sema_up(&lock->semaphore);
// }

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread(const struct lock *lock) {
	ASSERT(lock != NULL);

	return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init(struct condition *cond) {
	ASSERT(cond != NULL);

	list_init(&cond->waiters); // cond의 waiters만 init해주면 된다.
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait(struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter; // one semaphore element, waiter라 지칭하자

	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	sema_init(&waiter.semaphore, 0); //  semaphore_elem인 waiter의 semaphore의 value를 0으로 초기화
	list_push_back(&cond->waiters, &waiter.elem); // cond의 waiters 리스트에 waiter의 elem을 삽입, elem은 앞에서와 마찬가지로 관리용임
	lock_release(lock); // lock 해제해줘야함 -> 그래야 다른 thread가 lock 획득 후 시그널을 보낼 수 있음
	sema_down(&waiter.semaphore); // 
	lock_acquire(lock); // 깨어날 때 다시 lock을 획득해야함
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */

static bool
sema_priority_greater(const struct list_elem *lhs,
	const struct list_elem* rhs, void *aux UNUSED)
{
	struct semaphore *semal = &list_entry(lhs, struct semaphore_elem, elem)->semaphore;
	struct semaphore *semar = &list_entry(rhs, struct semaphore_elem, elem)->semaphore;
	return list_entry(list_min(&semal->waiters, thread_priority_greater, NULL), struct thread, elem)->priority
	   > list_entry(list_min(&semar->waiters, thread_priority_greater, NULL), struct thread, elem)->priority;
}


void
cond_signal(struct condition *cond, struct lock *lock UNUSED) {
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));


	if (!list_empty(&cond->waiters)) {
		struct list_elem *e = list_min(&cond->waiters, sema_priority_greater, NULL);
		list_remove(e);
		struct semaphore *sema = &list_entry(e, struct semaphore_elem, elem)->semaphore;
		sema_up(sema);
	}

}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast(struct condition *cond, struct lock *lock) {
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);

	while (!list_empty(&cond->waiters))
		cond_signal(cond, lock);
}


/* ________________ FROM HERE NEW FUNCTIONS ________________ */


