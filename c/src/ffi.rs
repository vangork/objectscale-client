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
    pub fn null() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0 || self.cap == 0
    }

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
