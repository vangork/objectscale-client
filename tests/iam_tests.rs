//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

mod common;
use objectscale_client::iam::{
    AccessKeyBuilder, GroupBuilder, GroupInlinePolicyBuilder, GroupPolicyAttachmentBuilder, IamTag,
    PermissionsBoundary, PolicyBuilder, RoleBuilder, RolePolicyAttachmentBuilder, UserBuilder,
    UserInlinePolicyBuilder, UserPolicyAttachmentBuilder,
};
use objectscale_client::tenancy::NamespaceBuilder;

const REPLICATION_GROUP: &str =
    "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";

#[test]
fn test_user() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_user";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let user_name = "iam_test_user";
    let arn = "urn:ecs:iam:::policy/ECSS3FullAccess";

    let user = UserBuilder::default()
        .user_name(user_name)
        .namespace(&namespace.id)
        .build()
        .expect("new user");
    let mut user = client.create_user(user).expect("create user");
    assert_eq!(user.user_name, user_name);
    assert_eq!(user.namespace, namespace.id);
    assert_eq!(user.tags.len(), 0);

    let tags = vec![IamTag {
        key: "key1".to_string(),
        value: "value1".to_string(),
    }];
    let permissions_boundary = PermissionsBoundary {
        permissions_boundary_arn: arn.to_string(),
        permissions_boundary_type: "".to_string(),
    };
    user.tags = tags.clone();
    user.permissions_boundary = permissions_boundary.clone();
    let state = client.update_user(user).expect("update user");
    assert_eq!(state, true);

    let user = client
        .get_user(user_name, namespace_name)
        .expect("get role");
    assert_eq!(user.user_name, user_name);
    assert_eq!(user.namespace, namespace.id);
    assert_eq!(user.tags, tags);
    assert_eq!(user.permissions_boundary.permissions_boundary_arn, arn);

    let users = client.list_users(namespace_name).expect("list users");
    assert!(users.contains(&user));

    client
        .delete_user(user_name, namespace_name)
        .expect("delete user");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_user_policy_attachment() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_user_policy_attachment";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let user_name = "iam_test_user_policy_attachment";
    let user = UserBuilder::default()
        .user_name(user_name)
        .namespace(&namespace.id)
        .build()
        .expect("user");
    let _ = client.create_user(user).expect("create user");

    let arn = "urn:ecs:iam:::policy/ECSS3FullAccess";
    let user_policy_attachment = UserPolicyAttachmentBuilder::default()
        .user_name(user_name)
        .policy_arn(arn)
        .namespace(namespace_name)
        .build()
        .expect("new user policy attachment");
    let user_policy_attachment = client
        .create_user_policy_attachment(user_policy_attachment)
        .expect("create user policy attachment");
    assert_eq!(user_policy_attachment.user_name, user_name);
    assert_eq!(user_policy_attachment.policy_arn, arn);
    assert_eq!(user_policy_attachment.namespace, namespace.id);

    let user_policy_attachments = client
        .list_user_policy_attachments(user_name, namespace_name)
        .expect("list user policy attachment");
    assert!(user_policy_attachments.contains(&user_policy_attachment));

    client
        .delete_user_policy_attachment(user_policy_attachment)
        .expect("delete user policy attachment");

    client
        .delete_user(user_name, namespace_name)
        .expect("delete user");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_access_key() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_access_key";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let user_name = "iam_test_access_key";
    let user = UserBuilder::default()
        .user_name(user_name)
        .namespace(&namespace.id)
        .build()
        .expect("user");
    let _ = client.create_user(user).expect("create user");

    let access_key = AccessKeyBuilder::default()
        .user_name(user_name)
        .namespace(namespace_name)
        .build()
        .expect("new access key");
    let mut access_key = client
        .create_access_key(access_key)
        .expect("create access key");
    let access_key_id = access_key.access_key_id.clone();
    assert_eq!(access_key.user_name, user_name);
    assert_eq!(access_key.namespace, namespace.id);

    let access_keys = client
        .list_access_keys(user_name, namespace_name)
        .expect("list access keys");
    assert_ne!(access_keys.len(), 0);

    access_key.status = "Inactive".to_string();
    let state = client
        .update_access_key(access_key)
        .expect("update access key");
    assert_eq!(state, true);

    client
        .delete_access_key(&access_key_id, user_name, namespace_name)
        .expect("delete access key");

    client
        .delete_user(user_name, namespace_name)
        .expect("delete user");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_policy() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_policy";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let policy_name = "iam_test_policy";
    let document = "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Action%22%3A%5B%22s3%3AListBucket%22%2C%22s3%3AListAllMyBuckets%22%5D%2C%22Resource%22%3A%22*%22%2C%22Effect%22%3A%22Allow%22%2C%22Sid%22%3A%22VisualEditor0%22%7D%5D%7D";
    let policy = PolicyBuilder::default()
        .policy_name(policy_name)
        .policy_document(document)
        .namespace(namespace_name)
        .build()
        .expect("new policy");
    let policy = client.create_policy(policy).expect("create policy");
    assert_eq!(policy.policy_name, policy_name);
    assert_eq!(policy.namespace, namespace.id);

    let get_policy = client
        .get_policy(&policy.arn, namespace_name)
        .expect("get policy");
    assert_eq!(policy, get_policy);

    let policies = client.list_policies(namespace_name).expect("list policies");
    assert!(policies.contains(&policy));

    client
        .delete_policy(&policy.arn, namespace_name)
        .expect("delete policy");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_group() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_group";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let group_name = "iam_test_group";
    let group = GroupBuilder::default()
        .group_name(group_name)
        .namespace(namespace_name)
        .build()
        .expect("new group");
    let group = client.create_group(group).expect("create group");
    assert_eq!(group.group_name, group_name);
    assert_eq!(group.namespace, namespace.id);

    let get_group = client
        .get_group(group_name, namespace_name)
        .expect("get group");
    assert_eq!(group, get_group);

    let groups = client.list_groups(namespace_name).expect("list groups");
    assert!(groups.contains(&group));

    client
        .delete_group(group_name, namespace_name)
        .expect("delete group");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_group_policy_attachment() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_group_policy_attachment";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let group_name = "iam_test_group_policy_attachment";
    let group = GroupBuilder::default()
        .group_name(group_name)
        .namespace(namespace_name)
        .build()
        .expect("new group");
    let _ = client.create_group(group).expect("create group");

    let arn = "urn:ecs:iam:::policy/ECSS3FullAccess";
    let group_policy_attachment = GroupPolicyAttachmentBuilder::default()
        .group_name(group_name)
        .policy_arn(arn)
        .namespace(namespace_name)
        .build()
        .expect("new group policy attachment");
    let group_policy_attachment = client
        .create_group_policy_attachment(group_policy_attachment)
        .expect("create group policy attachment");
    assert_eq!(group_policy_attachment.group_name, group_name);
    assert_eq!(group_policy_attachment.policy_arn, arn);
    assert_eq!(group_policy_attachment.namespace, namespace.id);

    let group_policy_attachments = client
        .list_group_policy_attachments(group_name, namespace_name)
        .expect("list group policy attachment");
    assert!(group_policy_attachments.contains(&group_policy_attachment));

    client
        .delete_group_policy_attachment(group_policy_attachment)
        .expect("delete group policy attachment");

    client
        .delete_group(group_name, namespace_name)
        .expect("delete group");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_role() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_role";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("build namespace");
    let namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let role_name = "iam_test_role";
    let description = "test role description";
    let duration = 9600;
    let assume_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:ecs:iam::ns1:root"]},"Action":"sts:AssumeRole"}]}"#;

    let role = RoleBuilder::default()
        .role_name(role_name)
        .description(description)
        .max_session_duration(duration)
        .assume_role_policy_document(assume_doc)
        .namespace(namespace_name)
        .build()
        .expect("new role");
    let mut role = client.create_role(role).expect("create role");
    assert_eq!(role.role_name, role_name);
    assert_eq!(role.description, description);
    assert_eq!(role.max_session_duration, duration);
    assert_eq!(role.namespace, namespace_name);
    assert_eq!(role.tags.len(), 0);

    let new_duration = 7200;
    let new_description = "new test role description";
    let arn = "urn:ecs:iam:::policy/IAMFullAccess";
    let permissions_boundary = PermissionsBoundary {
        permissions_boundary_arn: arn.to_string(),
        permissions_boundary_type: "".to_string(),
    };
    let tags = vec![IamTag {
        key: "key1".to_string(),
        value: "value1".to_string(),
    }];
    role.permissions_boundary = permissions_boundary;
    role.tags = tags.clone();
    role.max_session_duration = new_duration;
    role.description = new_description.to_string();
    let state = client.update_role(role).expect("update role");
    assert_eq!(state, true);

    let role = client
        .get_role(role_name, namespace_name)
        .expect("get role");
    assert_eq!(role.permissions_boundary.permissions_boundary_arn, arn);
    assert_eq!(role.role_name, role_name);
    assert_eq!(role.max_session_duration, new_duration);
    assert_eq!(role.description, new_description);
    assert_eq!(role.namespace, namespace_name);
    assert_eq!(role.tags, tags);

    let roles = client.list_roles(namespace_name).expect("list roles");
    assert!(roles.contains(&role));

    client
        .delete_role(role_name, namespace_name)
        .expect("delete role");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_role_policy_attachment() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_role_policy_attachment";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let role_name = "iam_test_role_policy_attachment";
    let assume_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:ecs:iam::ns1:root"]},"Action":"sts:AssumeRole"}]}"#;

    let role = RoleBuilder::default()
        .role_name(role_name)
        .namespace(namespace_name)
        .assume_role_policy_document(assume_doc)
        .build()
        .expect("new role");
    let _ = client.create_role(role).expect("create role");

    let arn = "urn:ecs:iam:::policy/ECSS3FullAccess";
    let role_policy_attachment = RolePolicyAttachmentBuilder::default()
        .role_name(role_name)
        .policy_arn(arn)
        .namespace(namespace_name)
        .build()
        .expect("role policy attachment");
    let role_policy_attachment = client
        .create_role_policy_attachment(role_policy_attachment)
        .expect("create role policy attachment");
    assert_eq!(role_policy_attachment.role_name, role_name);
    assert_eq!(role_policy_attachment.policy_arn, arn);
    assert_eq!(role_policy_attachment.namespace, namespace.id);

    let role_policy_attachments = client
        .list_role_policy_attachments(role_name, namespace_name)
        .expect("list role policy attachment");
    assert!(role_policy_attachments.contains(&role_policy_attachment));

    client
        .delete_role_policy_attachment(role_policy_attachment)
        .expect("delete role policy attachment");

    client
        .delete_role(role_name, namespace_name)
        .expect("delete role");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_user_inline_policy() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_user_inline_policy";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let user_name = "iam_test_user_inline_policy";
    let user = UserBuilder::default()
        .user_name(user_name)
        .namespace(&namespace.id)
        .build()
        .expect("build user");
    let _ = client.create_user(user).expect("create user");

    let policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListAttachedGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";
    let policy_name = "iam_test_user_inline_policy";
    let user_inline_policy = UserInlinePolicyBuilder::default()
        .user_name(user_name)
        .policy_name(policy_name)
        .policy_document(policy_document)
        .namespace(namespace_name)
        .build()
        .expect("build user inline policy");
    let mut user_inline_policy = client
        .create_user_inline_policy(user_inline_policy)
        .expect("create user inline policy");
    assert_eq!(user_inline_policy.user_name, user_name);
    assert_eq!(user_inline_policy.policy_name, policy_name);
    assert_eq!(user_inline_policy.namespace, namespace.id);

    let user_inline_policies = client
        .list_user_inline_policies(user_name, namespace_name)
        .expect("list user inline policy");
    assert!(user_inline_policies.contains(&user_inline_policy));

    user_inline_policy.policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D".to_string();
    let state = client
        .update_user_inline_policy(user_inline_policy)
        .expect("update user inline policy");
    assert!(state);
    let user_inline_policy = client
        .get_user_inline_policy(user_name, policy_name, namespace_name)
        .expect("get user inline policy");
    assert_eq!(user_inline_policy.user_name, user_name);
    assert_eq!(user_inline_policy.policy_name, policy_name);
    assert_eq!(user_inline_policy.namespace, namespace.id);

    client
        .delete_user_inline_policy(user_name, policy_name, namespace_name)
        .expect("delete user policy attachment");

    client
        .delete_user(user_name, namespace_name)
        .expect("delete user");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}

#[test]
fn test_group_inline_policy() {
    let mut client = common::create_management_client();

    let namespace_name = "iam_test_group_inline_policy";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace: objectscale_client::tenancy::Namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let group_name = "iam_test_group_inline_policy";
    let group = GroupBuilder::default()
        .group_name(group_name)
        .namespace(&namespace.id)
        .build()
        .expect("build group");
    let _ = client.create_group(group).expect("create group");

    let policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListAttachedGroupPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D";
    let policy_name = "iam_test_group_inline_policy";
    let group_inline_policy = GroupInlinePolicyBuilder::default()
        .group_name(group_name)
        .policy_name(policy_name)
        .policy_document(policy_document)
        .namespace(namespace_name)
        .build()
        .expect("build group inline policy");
    let mut group_inline_policy = client
        .create_group_inline_policy(group_inline_policy)
        .expect("create group inline policy");
    assert_eq!(group_inline_policy.group_name, group_name);
    assert_eq!(group_inline_policy.policy_name, policy_name);
    assert_eq!(group_inline_policy.namespace, namespace.id);

    let group_inline_policies = client
        .list_group_inline_policies(group_name, namespace_name)
        .expect("list group inline policy");
    assert!(group_inline_policies.contains(&group_inline_policy));

    group_inline_policy.policy_document = "%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22iam%3AListUsers%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListPolicies%22%2C%0A%20%20%20%20%20%20%20%20%22iam%3AListUserPolicies%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22*%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D".to_string();
    let state = client
        .update_group_inline_policy(group_inline_policy)
        .expect("update group inline policy");
    assert!(state);
    let group_inline_policy = client
        .get_group_inline_policy(group_name, policy_name, namespace_name)
        .expect("get group inline policy");
    assert_eq!(group_inline_policy.group_name, group_name);
    assert_eq!(group_inline_policy.policy_name, policy_name);
    assert_eq!(group_inline_policy.namespace, namespace.id);

    client
        .delete_group_inline_policy(group_name, policy_name, namespace_name)
        .expect("delete group policy attachment");

    client
        .delete_group(group_name, namespace_name)
        .expect("delete group");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}
