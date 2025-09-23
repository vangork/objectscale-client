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
use objectscale_client::tenancy::{
    Attribute, NamespaceBuilder, RetentionClass, RetentionClasses, UserMapping,
};

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_namespace";
    let replication_group =
        "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";

    let namespace = NamespaceBuilder::default()
        .name(name)
        .default_data_services_vpool(replication_group)
        .block_size(2)
        .notification_size(2)
        .retention_classes(RetentionClasses {
            retention_class: vec![RetentionClass {
                name: "r1".to_string(),
                period: 1,
            }],
        })
        .user_mapping(vec![UserMapping {
            attributes: vec![Attribute {
                key: "aa".to_string(),
                value: vec!["aa".to_string()],
            }],
            domain: "aa".to_string(),
            groups: vec!["aa".to_string()],
        }])
        .build()
        .expect("new namespace");
    let namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    println!("Created namespace: {:?}", namespace);
}
