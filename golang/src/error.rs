use crate::buffer::Buffer;
use errno::{set_errno, Errno};

pub fn clear_error() {
    set_errno(Errno(0));
}

pub fn set_error(msg: &str, errout: Option<&mut Buffer>) {
    if let Some(mb) = errout {
        *mb = Buffer::from_vec(msg.as_bytes().to_vec());
    }
    // TODO: should we set errno to something besides generic 1 always?
    set_errno(Errno(1));
}
