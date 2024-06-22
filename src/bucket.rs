//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

//! Implements the API interface for provisioning and managing buckets.
//!

pub struct Bucket {
    name: String,
}

impl Bucket {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    pub fn create_bucket(&self) {
        println!("create bucket: {}", self.name);
    }
}
