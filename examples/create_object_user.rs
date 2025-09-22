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
use objectscale_client::user::{ObjectUserBuilder, SecretKey, SwiftGroup, UserTag};

fn main() {
    let endpoint = "https://10.225.108.151:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_user";
    let namespace = "ns1";

    let user = ObjectUserBuilder::default()
        .name(name)
        .namespace(namespace)
        .tag(vec![UserTag {
            name: "name1".to_string(),
            value: "value1".to_string(),
        }])
        .secret_keys(vec![
            SecretKey::default(),
            SecretKey {
                existing_key_expiry_time_mins: "60".to_string(),
                ..Default::default()
            },
        ])
        .swift_group(SwiftGroup {
            password: "12345678".to_string(),
            groups_list: vec!["admin".to_string(), "users".to_string()],
            ..Default::default()
        })
        .build()
        .expect("new object user");
    let user = client.create_object_user(user).expect("create object user");

    println!("Created object user: {:?}", user);
}
