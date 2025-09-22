//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

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
