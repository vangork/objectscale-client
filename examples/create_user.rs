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
use objectscale_client::iam::{IamTag, PermissionsBoundary, UserBuilder};

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let user_name = "luis_user";
    let namespace = "ns1";
    let arn = "urn:ecs:iam:::policy/ECSS3FullAccess";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let user = UserBuilder::default()
        .user_name(user_name)
        .namespace(namespace)
        .tags(vec![IamTag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .permissions_boundary(PermissionsBoundary {
            permissions_boundary_arn: arn.to_string(),
            permissions_boundary_type: "".to_string(),
        })
        .build()
        .expect("user");
    let user = client.create_user(user).expect("create user");
    println!("Created user: {:?}", user);
}
