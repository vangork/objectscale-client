use std::mem;
use std::slice;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct RCString {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl RCString {
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        let rcstring = RCString {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        mem::forget(v);
        rcstring
    }

    pub fn to_vec(self) -> Vec<u8> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut v = unsafe { Vec::from_raw_parts(self.ptr, self.len, self.cap) };
        v.shrink_to_fit();
        v
    }

    pub fn from_str(str: &str) -> Self {
        Self::from_vec(str.as_bytes().to_vec())
    }

    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0 || self.cap == 0
    }

    pub fn to_string(&self) -> String {
        if self.is_empty() {
            String::new()
        } else {
            unsafe {
                let arr = slice::from_raw_parts(self.ptr, self.len);
                std::str::from_utf8(arr).expect("from utf8").to_string()
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn free_rcstring(rcstring: RCString) {
    let _ = rcstring.to_vec();
}

#[derive(Clone)]
#[repr(C)]
pub struct RCArray<T> where T: Clone {
    pub ptr: *mut T,
    pub len: usize,
    pub cap: usize,
}

impl<T> RCArray<T> where T: Clone {
    pub fn null() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    pub fn from_vec(v: Vec<T>) -> Self {
        let boxed_slice = v.into_boxed_slice();

        let arr = RCArray {
            ptr: boxed_slice.as_ptr() as *mut T,
            len: boxed_slice.len(),
            cap: boxed_slice.len(),
        };
        mem::forget(boxed_slice);
        arr
    }

    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0
    }

    pub fn to_vec(self) -> Vec<T> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut v = unsafe { Vec::from_raw_parts(self.ptr, self.len, self.cap) };
        v.shrink_to_fit();
        v
    }

    pub fn copy_to_vec(&self) -> Vec<T> {
        if self.is_empty() {
            vec![]
        } else {
            let mut v = Vec::with_capacity(self.len);
            unsafe {
                let arr = slice::from_raw_parts(self.ptr, self.len);
                v.extend_from_slice(arr);
                v
            }
        }
    }
}
