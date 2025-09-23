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
use objectscale_client::iam::GroupBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let group_name = "luis_group";
    let namespace = "ns1";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let group = GroupBuilder::default()
        .group_name(group_name)
        .namespace(namespace)
        .build()
        .expect("group");
    let group = client.create_group(group).expect("create group");
    println!("Created group: {:?}", group);

    let group = client.get_group(group_name, namespace).expect("get group");
    println!("Get group: {:?}", group);

    client
        .delete_group(group_name, namespace)
        .expect("delete group");
    println!("Deleted group: {}", group_name);

    let groups = client.list_groups(namespace).expect("list groups");
    println!("List groups: {:?}", groups);
}
