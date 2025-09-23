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

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_user";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut user = client
        .get_management_user(name)
        .expect("get management user");
    user.is_system_admin = true;
    user.is_system_monitor = true;
    user.is_security_admin = true;
    let state = client
        .update_management_user(user)
        .expect("update management user");

    println!("Update management user: {:?}", state);
}
