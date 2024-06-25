use crate::ffi::RCString;
use errno::{set_errno, Errno};

pub fn clear_error() {
    set_errno(Errno(0));
}

pub fn set_error(msg: &str, errout: Option<&mut RCString>) {
    if let Some(mb) = errout {
        *mb = RCString::from_str(msg);
    }
    // TODO: should we set errno to something besides generic 1 always?
    set_errno(Errno(1));
}
