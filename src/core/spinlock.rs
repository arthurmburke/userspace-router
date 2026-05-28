//! A spinlock for kernel free locking, intended to circumvent the need for system calls in DPDK threads.
//! 
//! [`SpinLock`] is a generic guard around a arbitrary type [`T`]. 
//! It provides interior mutability through its `with` method, 
//! which takes a closure that gets exclusive access to the data while the lock is held. 
//! 
//! The lock is a simple spinlock implemented with an `AtomicBool` and `core::hint::spin_loop()` for efficient waiting.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::cell::UnsafeCell;

/// A minimal spinlock; the global allocator can't rely on `std::sync::Mutex`
/// without risking reentrancy through the allocator itself.
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: all access to `data` goes through `with`, which holds the lock.
unsafe impl<T> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: we hold the lock, so we have exclusive access to `data`.
        let result = f(unsafe { &mut *self.data.get() });
        self.locked.store(false, Ordering::Release);
        result
    }

    pub fn lock(&self) -> Guard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: we hold the lock, so we have exclusive access to `data`.
        Guard {
            lock: self,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
    data: &'a mut T,
}

impl<'a, T> Drop for Guard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<'a, T> AsRef<T> for Guard<'a, T> {
    fn as_ref(&self) -> &T {
        self.data
    }
}

impl<'a, T> AsMut<T> for Guard<'a, T> {
    fn as_mut(&mut self) -> &mut T {
        self.data
    }
}