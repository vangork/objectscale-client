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

    let name = "luis_bucket";
    let namespace = "ns1";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    client
        .delete_bucket(name, namespace, false)
        .expect("delete bucket");
    println!("Deleted bucket: {:?}", name);
}
