//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

use objectscale_client::iam;
use pyo3::prelude::*;
use serde::Serialize;
use std::convert::From;

// IAM User access key
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct AccessKey {
    // The Id of this access key
    access_key_id: String,
    // The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
    create_date: String,
    // The secret key
    secret_access_key: String,
    // The status of the access key {Active | Inactive}. No need to set value during creation, by default is Active. Updatable
    status: String,
    // The name of the user that the access key is associated with. Required
    #[pyo3(set)]
    user_name: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::AccessKey> for AccessKey {
    fn from(access_key: iam::AccessKey) -> Self {
        Self {
            access_key_id: access_key.access_key_id,
            create_date: access_key.create_date,
            secret_access_key: access_key.secret_access_key,
            status: access_key.status,
            user_name: access_key.user_name,
            namespace: access_key.namespace,
        }
    }
}

impl From<AccessKey> for iam::AccessKey {
    fn from(access_key: AccessKey) -> Self {
        Self {
            access_key_id: access_key.access_key_id,
            create_date: access_key.create_date,
            secret_access_key: access_key.secret_access_key,
            status: access_key.status,
            user_name: access_key.user_name,
            namespace: access_key.namespace,
        }
    }
}

#[pymethods]
impl AccessKey {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct EntitiesForPolicy {
    // List of user names
    #[pyo3(set)]
    users: Vec<String>,
    // List of group names
    #[pyo3(set)]
    groups: Vec<String>,
    // List of role names
    #[pyo3(set)]
    roles: Vec<String>,
}

impl From<iam::EntitiesForPolicy> for EntitiesForPolicy {
    fn from(entities_for_policy: iam::EntitiesForPolicy) -> Self {
        Self {
            users: entities_for_policy.users,
            groups: entities_for_policy.groups,
            roles: entities_for_policy.roles,
        }
    }
}

impl From<EntitiesForPolicy> for iam::EntitiesForPolicy {
    fn from(entities_for_policy: EntitiesForPolicy) -> Self {
        Self {
            users: entities_for_policy.users,
            groups: entities_for_policy.groups,
            roles: entities_for_policy.roles,
        }
    }
}

#[pymethods]
impl EntitiesForPolicy {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// A Group is a collection of Users. You can use groups to specify permissions for a collection of users.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct Group {
    // Arn that identifies the Group.
    arn: String,
    // ISO 8601 format DateTime when group was created.
    create_date: String,
    // The path to the IAM Group.
    path: String,
    // Unique Id associated with the Group.
    group_id: String,
    // Simple name identifying the Group. Required.
    #[pyo3(set)]
    group_name: String,
    // Namespace. Required.
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::Group> for Group {
    fn from(group: iam::Group) -> Self {
        Self {
            arn: group.arn,
            create_date: group.create_date,
            path: group.path,
            group_id: group.group_id,
            group_name: group.group_name,
            namespace: group.namespace,
        }
    }
}

impl From<Group> for iam::Group {
    fn from(group: Group) -> Self {
        Self {
            arn: group.arn,
            create_date: group.create_date,
            path: group.path,
            group_id: group.group_id,
            group_name: group.group_name,
            namespace: group.namespace,
        }
    }
}

#[pymethods]
impl Group {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct GroupInlinePolicy {
    // Simple name identifying the group. Required
    #[pyo3(set)]
    group_name: String,
    // Simple name identifying the policy. Required
    #[pyo3(set)]
    policy_name: String,
    // The policy document in JSON format. Required
    #[pyo3(set)]
    policy_document: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::GroupInlinePolicy> for GroupInlinePolicy {
    fn from(group_inline_policy: iam::GroupInlinePolicy) -> Self {
        Self {
            group_name: group_inline_policy.group_name,
            policy_name: group_inline_policy.policy_name,
            policy_document: group_inline_policy.policy_document,
            namespace: group_inline_policy.namespace,
        }
    }
}

impl From<GroupInlinePolicy> for iam::GroupInlinePolicy {
    fn from(group_inline_policy: GroupInlinePolicy) -> Self {
        Self {
            group_name: group_inline_policy.group_name,
            policy_name: group_inline_policy.policy_name,
            policy_document: group_inline_policy.policy_document,
            namespace: group_inline_policy.namespace,
        }
    }
}

#[pymethods]
impl GroupInlinePolicy {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct GroupPolicyAttachment {
    // Name of the group to attach the policy. Required
    #[pyo3(set)]
    group_name: String,
    // Name of the policy to attach
    policy_name: String,
    // Arn of the policy to attach. Required
    #[pyo3(set)]
    policy_arn: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::GroupPolicyAttachment> for GroupPolicyAttachment {
    fn from(group_policy_attachment: iam::GroupPolicyAttachment) -> Self {
        Self {
            group_name: group_policy_attachment.group_name,
            policy_name: group_policy_attachment.policy_name,
            policy_arn: group_policy_attachment.policy_arn,
            namespace: group_policy_attachment.namespace,
        }
    }
}

impl From<GroupPolicyAttachment> for iam::GroupPolicyAttachment {
    fn from(group_policy_attachment: GroupPolicyAttachment) -> Self {
        Self {
            group_name: group_policy_attachment.group_name,
            policy_name: group_policy_attachment.policy_name,
            policy_arn: group_policy_attachment.policy_arn,
            namespace: group_policy_attachment.namespace,
        }
    }
}

#[pymethods]
impl GroupPolicyAttachment {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// Lables for IAM account, role and user.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct IamTag {
    // tag key
    #[pyo3(set)]
    key: String,
    // tag value
    #[pyo3(set)]
    value: String,
}

impl From<iam::IamTag> for IamTag {
    fn from(iam_tag: iam::IamTag) -> Self {
        Self {
            key: iam_tag.key,
            value: iam_tag.value,
        }
    }
}

impl From<IamTag> for iam::IamTag {
    fn from(iam_tag: IamTag) -> Self {
        Self {
            key: iam_tag.key,
            value: iam_tag.value,
        }
    }
}

#[pymethods]
impl IamTag {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct PermissionsBoundary {
    // The ARN of the policy set as permissions boundary. Default: "". Updatable
    #[pyo3(set)]
    permissions_boundary_arn: String,
    // The permissions boundary usage type that indicates what type of IAM resource is used as the permissions boundary for an entity. This data type can only have a value of Policy.
    #[pyo3(set)]
    permissions_boundary_type: String,
}

impl From<iam::PermissionsBoundary> for PermissionsBoundary {
    fn from(permissions_boundary: iam::PermissionsBoundary) -> Self {
        Self {
            permissions_boundary_arn: permissions_boundary.permissions_boundary_arn,
            permissions_boundary_type: permissions_boundary.permissions_boundary_type,
        }
    }
}

impl From<PermissionsBoundary> for iam::PermissionsBoundary {
    fn from(permissions_boundary: PermissionsBoundary) -> Self {
        Self {
            permissions_boundary_arn: permissions_boundary.permissions_boundary_arn,
            permissions_boundary_type: permissions_boundary.permissions_boundary_type,
        }
    }
}

#[pymethods]
impl PermissionsBoundary {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// IAM policies are documents in JSON format that define permissions for an operation regardless of the method that you use to perform the operation.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct Policy {
    // The resource name of the policy.
    arn: String,
    // The number of entities (users, groups, and roles) that the policy is attached to.
    attachment_count: i64,
    // The date and time, in ISO 8601 date-time format, when the policy was created.
    create_date: String,
    // The identifier for the version of the policy that is set as the default version.
    default_version_id: String,
    // A friendly description of the policy. Default: ""
    #[pyo3(set)]
    description: String,
    // Specifies whether the policy can be attached to user, group, or role.
    is_attachable: bool,
    // The path to the policy
    path: String,
    // Resource name of the policy that is used to set permissions boundary for the policy.
    permissions_boundary_usage_count: i64,
    // The stable and unique string identifying the policy.
    policy_id: String,
    // The friendly name of the policy. Required.
    #[pyo3(set)]
    policy_name: String,
    // The date and time, in ISO 8601 date-time format, when the policy was created.
    update_date: String,
    // The policy document in JSON format. Required. Updatable.
    #[pyo3(set)]
    policy_document: String,
    // Namespace. Required.
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::Policy> for Policy {
    fn from(policy: iam::Policy) -> Self {
        Self {
            arn: policy.arn,
            attachment_count: policy.attachment_count,
            create_date: policy.create_date,
            default_version_id: policy.default_version_id,
            description: policy.description,
            is_attachable: policy.is_attachable,
            path: policy.path,
            permissions_boundary_usage_count: policy.permissions_boundary_usage_count,
            policy_id: policy.policy_id,
            policy_name: policy.policy_name,
            update_date: policy.update_date,
            policy_document: policy.policy_document,
            namespace: policy.namespace,
        }
    }
}

impl From<Policy> for iam::Policy {
    fn from(policy: Policy) -> Self {
        Self {
            arn: policy.arn,
            attachment_count: policy.attachment_count,
            create_date: policy.create_date,
            default_version_id: policy.default_version_id,
            description: policy.description,
            is_attachable: policy.is_attachable,
            path: policy.path,
            permissions_boundary_usage_count: policy.permissions_boundary_usage_count,
            policy_id: policy.policy_id,
            policy_name: policy.policy_name,
            update_date: policy.update_date,
            policy_document: policy.policy_document,
            namespace: policy.namespace,
        }
    }
}

#[pymethods]
impl Policy {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// A role is similar to a user, in that it is an identity with permission policies that determine what the identity can and cannot do.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct Role {
    // Arn that identifies the role.
    arn: String,
    // The trust relationship policy document that grants an entity permission to assume the role. Required.
    #[pyo3(set)]
    assume_role_policy_document: String,
    // ISO 8601 DateTime when role was created.
    create_date: String,
    // The description of the IAM role. Default: "". Updatable
    #[pyo3(set)]
    description: String,
    // The maximum session duration (in seconds) that you want to set for the specified role. If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours. Default: 3600. Updatable
    #[pyo3(set)]
    max_session_duration: i64,
    // The path to the IAM role.
    path: String,
    // Unique Id associated with the role.
    role_id: String,
    // Simple name identifying the role. Required
    #[pyo3(set)]
    role_name: String,
    // The list of Tags associated with the role. Default: []. Updatable
    #[pyo3(set)]
    tags: Vec<IamTag>,
    // Permissions boundary. Default: see PermissionsBoundary. Updatable
    #[pyo3(set)]
    permissions_boundary: PermissionsBoundary,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::Role> for Role {
    fn from(role: iam::Role) -> Self {
        Self {
            arn: role.arn,
            assume_role_policy_document: role.assume_role_policy_document,
            create_date: role.create_date,
            description: role.description,
            max_session_duration: role.max_session_duration,
            path: role.path,
            role_id: role.role_id,
            role_name: role.role_name,
            tags: role.tags.into_iter().map(IamTag::from).collect(),
            permissions_boundary: PermissionsBoundary::from(role.permissions_boundary),
            namespace: role.namespace,
        }
    }
}

impl From<Role> for iam::Role {
    fn from(role: Role) -> Self {
        Self {
            arn: role.arn,
            assume_role_policy_document: role.assume_role_policy_document,
            create_date: role.create_date,
            description: role.description,
            max_session_duration: role.max_session_duration,
            path: role.path,
            role_id: role.role_id,
            role_name: role.role_name,
            tags: role.tags.into_iter().map(iam::IamTag::from).collect(),
            permissions_boundary: iam::PermissionsBoundary::from(role.permissions_boundary),
            namespace: role.namespace,
        }
    }
}

#[pymethods]
impl Role {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct RoleInlinePolicy {
    // Simple name identifying the role. Required
    #[pyo3(set)]
    role_name: String,
    // Simple name identifying the policy. Required
    #[pyo3(set)]
    policy_name: String,
    // The policy document in JSON format. Required
    #[pyo3(set)]
    policy_document: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::RoleInlinePolicy> for RoleInlinePolicy {
    fn from(role_inline_policy: iam::RoleInlinePolicy) -> Self {
        Self {
            role_name: role_inline_policy.role_name,
            policy_name: role_inline_policy.policy_name,
            policy_document: role_inline_policy.policy_document,
            namespace: role_inline_policy.namespace,
        }
    }
}

impl From<RoleInlinePolicy> for iam::RoleInlinePolicy {
    fn from(role_inline_policy: RoleInlinePolicy) -> Self {
        Self {
            role_name: role_inline_policy.role_name,
            policy_name: role_inline_policy.policy_name,
            policy_document: role_inline_policy.policy_document,
            namespace: role_inline_policy.namespace,
        }
    }
}

#[pymethods]
impl RoleInlinePolicy {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct RolePolicyAttachment {
    // Simple name identifying the role. Required
    #[pyo3(set)]
    role_name: String,
    //
    policy_name: String,
    // Arn that identifies the policy. Required
    #[pyo3(set)]
    policy_arn: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::RolePolicyAttachment> for RolePolicyAttachment {
    fn from(role_policy_attachment: iam::RolePolicyAttachment) -> Self {
        Self {
            role_name: role_policy_attachment.role_name,
            policy_name: role_policy_attachment.policy_name,
            policy_arn: role_policy_attachment.policy_arn,
            namespace: role_policy_attachment.namespace,
        }
    }
}

impl From<RolePolicyAttachment> for iam::RolePolicyAttachment {
    fn from(role_policy_attachment: RolePolicyAttachment) -> Self {
        Self {
            role_name: role_policy_attachment.role_name,
            policy_name: role_policy_attachment.policy_name,
            policy_arn: role_policy_attachment.policy_arn,
            namespace: role_policy_attachment.namespace,
        }
    }
}

#[pymethods]
impl RolePolicyAttachment {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// ObjectScale IAM features for S3 work with SAML identity providers to handle authentication and SAML Assertion generation
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct SamlProvider {
    // Arn that identifies the SAML Identity Provider.
    arn: String,
    // The name of the provider. Required
    #[pyo3(set)]
    name: String,
    // ISO 8601 format DateTime when SAML Identity Provider was created.
    create_date: String,
    // ISO 8601 format DateTime when SAML Identity Provider will be valid.
    valid_until: String,
    // An XML document generated by an identity provider (IdP) that supports SAML 2.0. Required. Updatable
    #[pyo3(set)]
    metadata_docucment: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::SamlProvider> for SamlProvider {
    fn from(saml_provider: iam::SamlProvider) -> Self {
        Self {
            arn: saml_provider.arn,
            name: saml_provider.name,
            create_date: saml_provider.create_date,
            valid_until: saml_provider.valid_until,
            metadata_docucment: saml_provider.metadata_docucment,
            namespace: saml_provider.namespace,
        }
    }
}

impl From<SamlProvider> for iam::SamlProvider {
    fn from(saml_provider: SamlProvider) -> Self {
        Self {
            arn: saml_provider.arn,
            name: saml_provider.name,
            create_date: saml_provider.create_date,
            valid_until: saml_provider.valid_until,
            metadata_docucment: saml_provider.metadata_docucment,
            namespace: saml_provider.namespace,
        }
    }
}

#[pymethods]
impl SamlProvider {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// In ObjectScale, an IAM User is a person or application in the account.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct User {
    // Arn that identifies the user.
    arn: String,
    // ISO 8601 format DateTime when user was created.
    create_date: String,
    // The path to the IAM User.
    path: String,
    // Permissions boundary. Default: see PermissionsBoundary. Updatable
    #[pyo3(set)]
    permissions_boundary: PermissionsBoundary,
    // Unique Id associated with the User.
    user_id: String,
    // Simple name identifying the User. Required
    #[pyo3(set)]
    user_name: String,
    // List of Tags associated with the User. Default: []. Updatable
    #[pyo3(set)]
    tags: Vec<IamTag>,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::User> for User {
    fn from(user: iam::User) -> Self {
        Self {
            arn: user.arn,
            create_date: user.create_date,
            path: user.path,
            permissions_boundary: PermissionsBoundary::from(user.permissions_boundary),
            user_id: user.user_id,
            user_name: user.user_name,
            tags: user.tags.into_iter().map(IamTag::from).collect(),
            namespace: user.namespace,
        }
    }
}

impl From<User> for iam::User {
    fn from(user: User) -> Self {
        Self {
            arn: user.arn,
            create_date: user.create_date,
            path: user.path,
            permissions_boundary: iam::PermissionsBoundary::from(user.permissions_boundary),
            user_id: user.user_id,
            user_name: user.user_name,
            tags: user.tags.into_iter().map(iam::IamTag::from).collect(),
            namespace: user.namespace,
        }
    }
}

#[pymethods]
impl User {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct UserGroupMembership {
    //
    #[pyo3(set)]
    user_name: String,
    //
    #[pyo3(set)]
    group_name: String,
    //
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::UserGroupMembership> for UserGroupMembership {
    fn from(user_group_membership: iam::UserGroupMembership) -> Self {
        Self {
            user_name: user_group_membership.user_name,
            group_name: user_group_membership.group_name,
            namespace: user_group_membership.namespace,
        }
    }
}

impl From<UserGroupMembership> for iam::UserGroupMembership {
    fn from(user_group_membership: UserGroupMembership) -> Self {
        Self {
            user_name: user_group_membership.user_name,
            group_name: user_group_membership.group_name,
            namespace: user_group_membership.namespace,
        }
    }
}

#[pymethods]
impl UserGroupMembership {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct UserInlinePolicy {
    // Simple name identifying the user. Required
    #[pyo3(set)]
    user_name: String,
    // Simple name identifying the policy. Required
    #[pyo3(set)]
    policy_name: String,
    // The policy document in JSON format. Required
    #[pyo3(set)]
    policy_document: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::UserInlinePolicy> for UserInlinePolicy {
    fn from(user_inline_policy: iam::UserInlinePolicy) -> Self {
        Self {
            user_name: user_inline_policy.user_name,
            policy_name: user_inline_policy.policy_name,
            policy_document: user_inline_policy.policy_document,
            namespace: user_inline_policy.namespace,
        }
    }
}

impl From<UserInlinePolicy> for iam::UserInlinePolicy {
    fn from(user_inline_policy: UserInlinePolicy) -> Self {
        Self {
            user_name: user_inline_policy.user_name,
            policy_name: user_inline_policy.policy_name,
            policy_document: user_inline_policy.policy_document,
            namespace: user_inline_policy.namespace,
        }
    }
}

#[pymethods]
impl UserInlinePolicy {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

//
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct UserPolicyAttachment {
    // Username of the user to attach the policy. Required
    #[pyo3(set)]
    user_name: String,
    // Name of the policy
    policy_name: String,
    // Arn of the policy to attach. Required
    #[pyo3(set)]
    policy_arn: String,
    // Namespace. Required
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::UserPolicyAttachment> for UserPolicyAttachment {
    fn from(user_policy_attachment: iam::UserPolicyAttachment) -> Self {
        Self {
            user_name: user_policy_attachment.user_name,
            policy_name: user_policy_attachment.policy_name,
            policy_arn: user_policy_attachment.policy_arn,
            namespace: user_policy_attachment.namespace,
        }
    }
}

impl From<UserPolicyAttachment> for iam::UserPolicyAttachment {
    fn from(user_policy_attachment: UserPolicyAttachment) -> Self {
        Self {
            user_name: user_policy_attachment.user_name,
            policy_name: user_policy_attachment.policy_name,
            policy_arn: user_policy_attachment.policy_arn,
            namespace: user_policy_attachment.namespace,
        }
    }
}

#[pymethods]
impl UserPolicyAttachment {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}
