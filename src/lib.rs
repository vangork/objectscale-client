//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//

#![allow(dead_code)]
#![deny(
    clippy::all,
    clippy::cargo,
    clippy::else_if_without_else,
    clippy::empty_line_after_outer_attr,
    clippy::multiple_inherent_impl,
    clippy::mut_mut,
    clippy::path_buf_push_overwrite
)]
#![warn(
    clippy::cargo_common_metadata,
    clippy::mutex_integer,
    clippy::needless_borrow,
    clippy::similar_names
)]
#![allow(clippy::multiple_crate_versions, clippy::needless_doctest_main)]

//! A Rust client for [ObjectScale].
//!
//! [ObjectScale] ObjectScale is high-performance containerized object storage
//! built for the toughest applications and workloads— AI, analytics and more.
//!
//! ObjectScale client in Rust provides a few APIs at high level:
//! * [Client] creates an ObjectScale client.
//! * [Bucket] is for provisioning and managing buckets.
//! * [IAM] is for identity and access management operations.
//!
//! [ObjectScale]: https://www.dell.com/en-hk/dt/storage/objectscale.htm
//! [Client]: crate::client
//! [IAM]: crate::iam
//! [Bucket]: crate::bucket
//!

pub mod bucket;
pub mod client;
pub mod iam;
mod response;
