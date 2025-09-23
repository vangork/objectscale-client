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
use objectscale_client::iam::UserInlinePolicyBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let user_name = "luis_user";
    let namespace = "ns1";

    let policy_name = "inline_policy_1";
    let policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListAttachedGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";
    let new_policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let user_inline_policy = UserInlinePolicyBuilder::default()
        .user_name(user_name)
        .policy_name(policy_name)
        .policy_document(policy_document)
        .namespace(namespace)
        .build()
        .expect("build user inline policy");

    let mut user_inline_policy = client
        .create_user_inline_policy(user_inline_policy)
        .expect("create user inline policy");
    println!("Created user inline policy: {:?}", user_inline_policy);

    user_inline_policy.policy_document = new_policy_document.to_string();
    let state = client
        .update_user_inline_policy(user_inline_policy)
        .expect("update user inline policy");
    println!("Update user inline policy: {}", state);

    let user_inline_policy = client
        .get_user_inline_policy(user_name, policy_name, namespace)
        .expect("get user inline policy");
    println!("Got user inline policy: {:?}", user_inline_policy);

    let user_inline_policies = client
        .list_user_inline_policies(user_name, namespace)
        .expect("list user inline policies");
    println!("List user inline policies: {:?}", user_inline_policies);

    client
        .delete_user_inline_policy(user_name, policy_name, namespace)
        .expect("delete user inline policy");
    println!("Deleted user inline policy");

    let user_inline_policies = client
        .list_user_inline_policies(user_name, namespace)
        .expect("list user inline policies");
    println!("List user inline policies: {:?}", user_inline_policies);
}
