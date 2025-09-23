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

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let mut store = client.get_vdc_keystore().expect("get vdc keystore");
    println!("Get vdc keystore: {:?}", store);

    store.chain = "chain".to_string();
    store.private_key = "pvk".to_string();
    let state = client
        .update_vdc_keystore(store)
        .expect("update vdc keystore");
    println!("Updated vdc keystore: {:?}", state);
}
