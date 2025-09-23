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
// use objectscale_client::provisioning::StoragePoolBuilder;

fn main() {
    let endpoint = "https://10.225.108.151:4443";
    let password = "Password123!";
    //let endpoint = "https://10.245.131.122:4443";
    //let password = "ChangeMe";
    let username = "root";
    let insecure = true;

    //let id = "urn:storageos:VirtualArray:2a36f1a7-4281-453d-8927-788f8033416b";
    //let id = "urn:storageos:VirtualArray:45925e36-6317-481f-9671-845d3e9b585a";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    // let mut sp = StoragePoolBuilder::default()
    //     .name("sp1")
    //     .description("sp1 description")
    //     .label("DRIVE_TECH_HDD")
    //     .drive_technology("HDD")
    //     .build()
    //     .expect("build storage pool");
    // sp.number_of_code_blocks = 2;
    // sp.number_of_data_blocks = 2;
    // let state = client.create_storage_pool(sp).expect("create storage pool");
    // println!("Created storage pool: {:?}", state);

    // let sp = client.get_storage_pool(id).expect("get storage pool");
    // println!("Get storage pool: {:?}", sp);

    // sp.name = "sp2".to_string();
    // sp.description = "sp2 description".to_string();
    // sp.warning_alert_at = 35;
    // sp.error_alert_at = 20;
    // sp.critical_alert_at = 15;
    // let state = client.update_storage_pool(sp).expect("update storage pool");
    // println!("Updated storage pool: {:?}", state);

    let sps = client.list_storage_pools().expect("list storage pools");
    println!("List storage pools: {:?}", sps);
}
