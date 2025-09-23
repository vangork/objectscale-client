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
use objectscale_client::user::UserTag;

fn main() {
    let endpoint = "https://10.225.108.151:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_user";
    let namespace = "ns1";

    let mut user = client
        .get_object_user(name, namespace)
        .expect("get object user");
    user.locked = true;
    user.tag = vec![UserTag {
        name: "name2".to_string(),
        value: "value2".to_string(),
    }];
    user.secret_keys.pop();
    user.swift_group.password = "123456789".to_string();
    user.swift_group.groups_list = vec!["admin".to_string()];
    let state = client.update_object_user(user).expect("update object user");

    println!("Update object user: {:?}", state);
}
