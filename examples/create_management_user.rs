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
use objectscale_client::user::ManagementUserBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_user";
    let password = "Password123!";

    let user = ManagementUserBuilder::default()
        .user_id(name)
        .password(password)
        .is_system_admin(true)
        .build()
        .expect("new management user");
    let user = client.create_management_user(user).expect("create user");

    println!("Created management user: {:?}", user);
}
