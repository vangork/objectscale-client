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
use objectscale_client::iam::RoleInlinePolicyBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let role_name = "luis_role";
    let namespace = "ns1";

    let policy_name = "inline_policy_1";
    let policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22s3%3AGetObject%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";
    let new_policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22s3%3AListAllMyBuckets%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let role_inline_policy = RoleInlinePolicyBuilder::default()
        .role_name(role_name)
        .policy_name(policy_name)
        .policy_document(policy_document)
        .namespace(namespace)
        .build()
        .expect("build role inline policy");

    let mut role_inline_policy = client
        .create_role_inline_policy(role_inline_policy)
        .expect("create role inline policy");
    println!("Created role inline policy: {:?}", role_inline_policy);

    role_inline_policy.policy_document = new_policy_document.to_string();
    let state = client
        .update_role_inline_policy(role_inline_policy)
        .expect("update role inline policy");
    println!("Update role inline policy: {}", state);

    let role_inline_policy = client
        .get_role_inline_policy(role_name, policy_name, namespace)
        .expect("get role inline policy");
    println!("Got role inline policy: {:?}", role_inline_policy);

    let role_inline_policies = client
        .list_role_inline_policies(role_name, namespace)
        .expect("list role inline policies");
    println!("List role inline policies: {:?}", role_inline_policies);

    client
        .delete_role_inline_policy(role_name, policy_name, namespace)
        .expect("delete role inline policy");
    println!("Deleted role inline policy");

    let role_inline_policies = client
        .list_role_inline_policies(role_name, namespace)
        .expect("list role inline policies");
    println!("List role inline policies: {:?}", role_inline_policies);
}
