//! A malloc-free object pool for fixed-size items, initialized before mempools
//! are used.
//!
//! [`ObjectPool::alloc`] hands back a [`PoolObj`] RAII handle that returns its
//! slot to the pool on drop. Allocation and release are O(1): a free-list
//! pop/push, never a scan.
//!
//! `alloc` takes `&self`, so any number of handles can be live at once. The
//! per-slot [`UnsafeCell`] is what makes mutating a slot behind a shared borrow
//! sound, and distinct handles always address distinct slots, so the `&mut T`s
//! they hand out never alias. The pool is `!Sync`: it is a single-threaded
//! (e.g. per-lcore) pool and must not be used reentrantly.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use std::mem::{MaybeUninit, size_of};

use crate::core::bitmask::Bitmask;

/// Free-slot bookkeeping, borrowed `&mut` only transiently inside a single
/// `alloc`/release call — never held across calls, never across threads.
struct FreeState {
    /// Bit set => slot currently allocated. Kept for O(1) double-free /
    /// ownership checks; the list is what makes allocation fast.
    used: Bitmask,
    /// Stack of free indices: `alloc` pops, release pushes. Seeded in reverse
    /// so a fresh pool hands out ascending indices, and sized to `capacity`
    /// up front so the hot path never reallocates.
    list: Vec<usize>,
}

pub struct ObjectPool<T> {
    /// Backing storage. Per-element `UnsafeCell` so two live handles can hold
    /// `&mut T` into different slots at the same time without aliasing.
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
    free: UnsafeCell<FreeState>,
}

impl<T> ObjectPool<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(
            size_of::<T>() != 0,
            "ObjectPool does not support zero-sized types"
        );
        
        Self {
            slots: (0..capacity)
                .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            free: UnsafeCell::new(FreeState {
                used: Bitmask::new(capacity),
                list: (0..capacity).rev().collect(),
            }),
        }
    }

    /// Total number of slots.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Number of slots currently free.
    #[inline]
    pub fn available(&self) -> usize {
        // SAFETY: transient shared read; no `&mut FreeState` is live here.
        unsafe { (*self.free.get()).list.len() }
    }

    /// Claim a free slot, move `value` into it, and return an owning handle.
    ///
    /// O(1): pops one index off the free-list — no scanning, however full the
    /// pool is. Returns `None` when exhausted. Takes `&self`, so any number of
    /// handles may be live simultaneously.
    #[inline]
    pub fn alloc(&self, value: T) -> Option<Obj<'_, T>> {
        let index = {
            // SAFETY: exclusive borrow dropped before we return; the pool is
            // single-threaded (`!Sync`) and not used reentrantly.
            let free = unsafe { &mut *self.free.get() };
            let index = free.list.pop()?;
            debug_assert!(!free.used.is_set(index), "free-list yielded an in-use slot");
            free.used.set(index);
            index
        };

        // SAFETY: `index` was free, so the slot holds no live value. The
        // pointer comes straight from the slot's `UnsafeCell` (not derived from
        // a `&self` reference), and `MaybeUninit<T>` shares `T`'s layout.
        let value = unsafe {
            let cell = self.slots[index].get();
            (*cell).write(value);
            cell as *mut T
        };

        Some(Obj { pool: self, index, value })
    }

    /// Return slot `index` to the free-list, optionally running the value's
    /// destructor first (`drop_value == false` when the value has been moved
    /// out already).
    ///
    /// SAFETY: the caller must exclusively own slot `index` (the single handle
    /// holding it does) and must not release the same live allocation twice.
    #[inline]
    fn release(&self, index: usize, drop_value: bool) {
        if drop_value {
            // SAFETY: the owning handle keeps the value live and unaliased.
            unsafe { (*self.slots[index].get()).assume_init_drop() };
        }
        // SAFETY: transient exclusive borrow; single-threaded, non-reentrant.
        let free = unsafe { &mut *self.free.get() };
        debug_assert!(free.used.is_set(index), "double free of pool slot");
        free.used.clear(index);
        free.list.push(index);
    }
}

impl<T> Drop for ObjectPool<T> {
    fn drop(&mut self) {
        // Drop any values still checked out — e.g. a handle leaked via
        // `mem::forget`. `&mut self` lets us reach the cell without `unsafe`.
        let free = self.free.get_mut();
        for index in 0..self.slots.len() {
            if free.used.is_set(index) {
                // SAFETY: bit set => the slot holds a live, not-yet-released
                // value; nothing else references it during pool teardown.
                unsafe { (*self.slots[index].get()).assume_init_drop() };
            }
        }
    }
}

// Auto traits: `UnsafeCell` makes `ObjectPool` `!Sync` (correct — `alloc`
// mutates shared state without synchronisation), while it stays `Send` when
// `T: Send`. `PoolObj` borrows the `!Sync` pool and holds a raw pointer, so it
// is `!Send`/`!Sync` — handles never leave their thread. No manual impls.

/// An owning handle to one slot in an [`ObjectPool`]. Dropping it runs the
/// value's destructor and returns the slot to the pool.
pub struct Obj<'a, T> {
    pool: &'a ObjectPool<T>,
    index: usize,
    /// Points into `pool.slots[index]`; valid for `'a` because the shared
    /// borrow of `pool` keeps the backing allocation pinned and alive.
    value: *mut T,
}

impl<T> Obj<'_, T> {
    /// The slot index backing this handle.
    #[inline]
    pub fn index(&self) -> usize {
        self.index
    }

    /// Move the value out, freeing the slot without running its destructor.
    pub fn into_inner(self) -> T {
        // SAFETY: we own the value; read it out by value.
        let value = unsafe { core::ptr::read(self.value) };
        let pool = self.pool;
        let index = self.index;
        // Stop `Drop` from releasing the slot a second time / dropping the
        // moved-out value.
        core::mem::forget(self);
        // The value has moved out, so do NOT drop it here.
        pool.release(index, false);
        value
    }
}

impl<T> AsRef<T> for Obj<'_, T> {
    #[inline]
    fn as_ref(&self) -> &T {
        // SAFETY: the slot holds a live value for this handle's lifetime;
        // `&self` bounds the shared borrow.
        unsafe { &*self.value }
    }
}

impl<T> AsMut<T> for Obj<'_, T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        // SAFETY: `&mut self` gives exclusive access to this handle's slot.
        unsafe { &mut *self.value }
    }
}

impl<T> Deref for Obj<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.as_ref()
    }
}

impl<T> DerefMut for Obj<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.as_mut()
    }
}

impl<T> Drop for Obj<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.pool.release(self.index, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Increments a shared counter when dropped, so tests can assert exactly
    /// how many times values are destroyed.
    struct Dropper(Rc<Cell<usize>>);
    impl Drop for Dropper {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn many_handles_live_at_once() {
        let pool = ObjectPool::new(4);
        let a = pool.alloc(1u32).unwrap();
        let b = pool.alloc(2u32).unwrap();
        let c = pool.alloc(3u32).unwrap();
        assert_eq!(*a + *b + *c, 6);
        assert_eq!(pool.available(), 1);
        assert_eq!(pool.capacity(), 4);
    }

    #[test]
    fn exhaustion_returns_none() {
        let pool = ObjectPool::new(1);
        let _a = pool.alloc(10u32).unwrap();
        assert!(pool.alloc(20u32).is_none());
    }

    #[test]
    fn slot_is_reused_after_drop() {
        let pool = ObjectPool::new(1);
        let a = pool.alloc(10u32).unwrap();
        let i = a.index();
        drop(a);
        let b = pool.alloc(20u32).unwrap();
        assert_eq!(b.index(), i);
        assert_eq!(*b, 20);
    }

    #[test]
    fn value_dropped_once_on_handle_drop() {
        let n = Rc::new(Cell::new(0));
        let pool = ObjectPool::new(2);
        {
            let _h = pool.alloc(Dropper(n.clone())).unwrap();
        }
        assert_eq!(n.get(), 1);
    }

    #[test]
    fn pool_drop_releases_leaked_handle() {
        let n = Rc::new(Cell::new(0));
        let pool = ObjectPool::new(2);
        let h = pool.alloc(Dropper(n.clone())).unwrap();
        std::mem::forget(h); // slot stays "used"; the borrow ends
        assert_eq!(n.get(), 0);
        drop(pool);
        assert_eq!(n.get(), 1); // teardown drops the live value
    }

    #[test]
    fn into_inner_moves_without_double_drop() {
        let n = Rc::new(Cell::new(0));
        let pool = ObjectPool::new(2);
        let h = pool.alloc(Dropper(n.clone())).unwrap();
        let v = h.into_inner();
        assert_eq!(n.get(), 0); // not dropped by releasing the slot
        assert_eq!(pool.available(), 2); // slot returned
        drop(v);
        assert_eq!(n.get(), 1); // dropped exactly once, by the caller
    }
}
