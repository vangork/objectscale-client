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
use objectscale_client::iam::GroupInlinePolicyBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let group_name = "luis_group";
    let namespace = "ns1";

    let policy_name = "inline_policy_1";
    let policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListAttachedGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";
    let new_policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let group_inline_policy = GroupInlinePolicyBuilder::default()
        .group_name(group_name)
        .policy_name(policy_name)
        .policy_document(policy_document)
        .namespace(namespace)
        .build()
        .expect("build group inline policy");

    let mut group_inline_policy = client
        .create_group_inline_policy(group_inline_policy)
        .expect("create group inline policy");
    println!("Created group inline policy: {:?}", group_inline_policy);

    group_inline_policy.policy_document = new_policy_document.to_string();
    let state = client
        .update_group_inline_policy(group_inline_policy)
        .expect("update group inline policy");
    println!("Update group inline policy: {}", state);

    let group_inline_policy = client
        .get_group_inline_policy(group_name, policy_name, namespace)
        .expect("get group inline policy");
    println!("Got group inline policy: {:?}", group_inline_policy);

    let group_inline_policies = client
        .list_group_inline_policies(group_name, namespace)
        .expect("list group inline policies");
    println!("List group inline policies: {:?}", group_inline_policies);

    client
        .delete_group_inline_policy(group_name, policy_name, namespace)
        .expect("delete group inline policy");
    println!("Deleted group inline policy");

    let group_inline_policies = client
        .list_group_inline_policies(group_name, namespace)
        .expect("list group inline policies");
    println!("List group inline policies: {:?}", group_inline_policies);
}
