use core::prelude::*;
use core::cell::UnsafeCell;
use core::ops::{Deref,DerefMut};
use core::atomic::{fence, Ordering, AtomicBool};

pub struct Mutex<T> {
    pub data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> { }
unsafe impl<T: Send> Sync for Mutex<T> { }

pub struct HeldMutex<'a, T: 'a> {
    mutex: &'a Mutex<T>,
}

impl<T> Mutex<T> {
    pub fn new(t: T) -> Mutex<T> {
        Mutex { data: UnsafeCell::new(t) }
    }

    pub fn lock(&self) -> HeldMutex<T> {
        HeldMutex { mutex: self }
    }

    fn unlock(&self) {
    }
}

impl<'lock, T> Deref for HeldMutex<'lock, T> {
    type Target = T;

    fn deref<'a>(&'a self) -> &'a T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'lock, T> DerefMut for HeldMutex<'lock, T> {
    fn deref_mut<'a>(&'a mut self) -> &'a mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

#[unsafe_destructor]
impl<'lock, T> Drop for HeldMutex<'lock, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

#[macro_export]
macro_rules! mutex {
    ($val:expr) => (
        $crate::mutex::Mutex {
            data: ::core::cell::UnsafeCell { value: $val }
        });
    ($ty:ty, $val:expr) => (
        $crate::mutex::Mutex<$ty> {
            data: ::core::cell::UnsafeCell<$ty> { value: $val }
        });
}
