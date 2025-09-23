//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

use objectscale_client::client::ManagementClient;
use objectscale_client::provisioning::BucketTag;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_bucket";
    let namespace = "ns1";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut bucket = client.get_bucket(name, namespace).expect("get bucket");
    bucket.owner = "object_admin1".to_string();
    bucket.tags = vec![BucketTag {
        key: "key2".to_string(),
        value: "value2".to_string(),
    }];
    //bucket.auto_commit_period = 200;
    bucket.retention = 250;
    bucket.min_max_governor.enforce_retention = true;
    bucket.min_max_governor.maximum_fixed_retention = 300;
    // bucket.is_object_lock_enabled = true;
    // bucket.default_object_lock_retention_mode = "COMPLIANCE".to_string();
    // bucket.default_object_lock_retention_years = 0;
    // bucket.default_object_lock_retention_days = 1;
    // bucket.default_group = "yl".to_string();
    // bucket.default_group_dir_read_permission = false;
    // bucket.default_group_file_read_permission = false;
    // bucket.versioning_status = "Suspended".to_string();
    // bucket.block_size = 300;
    // bucket.notification_size = 200;
    // bucket.audit_delete_expiration = -2;
    // bucket.is_stale_allowed = true;
    // bucket.is_object_lock_with_ado_allowed = true;
    // bucket.local_object_metadata_reads = true;
    bucket.search_metadata.is_enabled = false;

    let state = client.update_bucket(bucket).expect("update bucket");

    println!("Update bucket: {:?}", state);
}
