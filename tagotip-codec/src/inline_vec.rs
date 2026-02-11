use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr;
use core::slice;

/// A fixed-capacity vector stored inline (on the stack). No heap allocation.
///
/// This type does NOT call `Drop` on contained elements. It is intended for
/// types that are trivially destructible (references, primitive types, etc.).
pub struct InlineVec<T, const N: usize> {
    data: [MaybeUninit<T>; N],
    len: usize,
}

impl<T, const N: usize> InlineVec<T, N> {
    /// Creates an empty `InlineVec`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // SAFETY: An uninitialized array of MaybeUninit is valid.
            data: unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() },
            len: 0,
        }
    }

    /// Returns the number of elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the maximum capacity.
    pub fn capacity(&self) -> usize {
        N
    }

    /// Pushes an element. Returns `Err(value)` if full.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.len >= N {
            return Err(value);
        }
        // SAFETY: self.len < N, so this index is valid.
        unsafe {
            ptr::write(self.data[self.len].as_mut_ptr(), value);
        }
        self.len += 1;
        Ok(())
    }

    /// Returns a slice of the initialized elements.
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: elements 0..self.len are initialized.
        unsafe { slice::from_raw_parts(self.data.as_ptr().cast::<T>(), self.len) }
    }

    /// Returns a mutable slice of the initialized elements.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: elements 0..self.len are initialized.
        unsafe { slice::from_raw_parts_mut(self.data.as_mut_ptr().cast::<T>(), self.len) }
    }

    /// Returns a reference to the last element, if any.
    pub fn last(&self) -> Option<&T> {
        if self.len == 0 {
            None
        } else {
            // SAFETY: self.len - 1 is initialized.
            Some(unsafe { &*self.data[self.len - 1].as_ptr() })
        }
    }

    /// Removes and returns the last element, if any.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            // SAFETY: self.len was initialized before decrement.
            Some(unsafe { ptr::read(self.data[self.len].as_ptr()) })
        }
    }

    /// Clears the vector, setting length to 0.
    /// Does NOT call drop on contained elements.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Returns an iterator over the elements.
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<T, const N: usize> Default for InlineVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Deref for InlineVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const N: usize> DerefMut for InlineVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T: core::fmt::Debug, const N: usize> core::fmt::Debug for InlineVec<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice().iter()).finish()
    }
}

impl<T: PartialEq, const N: usize> PartialEq for InlineVec<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq, const N: usize> Eq for InlineVec<T, N> {}

impl<T: Clone, const N: usize> Clone for InlineVec<T, N> {
    fn clone(&self) -> Self {
        let mut new = Self::new();
        for item in self.as_slice() {
            // Won't fail because we're cloning same-capacity.
            let _ = new.push(item.clone());
        }
        new
    }
}
