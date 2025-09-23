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

    let id = "luis_namespace";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let namespace = client.get_namespace(id).expect("get namespace");
    println!("Get namespace: {:?}", namespace);
}
