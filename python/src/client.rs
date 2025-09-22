//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

#![allow(unused_imports)]

use crate::iam::{
    AccessKey, EntitiesForPolicy, Group, GroupInlinePolicy, GroupPolicyAttachment, IamTag,
    PermissionsBoundary, Policy, Role, RolePolicyAttachment, SamlProvider, User,
    UserGroupMembership, UserInlinePolicy, UserPolicyAttachment,
};
use crate::provisioning::{
    Bucket, BucketTag, MetaData, MinMaxGovernor, ProvisioningLink, SearchMetaData, StoragePool,
    Vdc, VdcKeystore,
};
use crate::replication::{ReplicationGroup, VarrayMapping};
use crate::tenancy::{
    Attribute, Namespace, RetentionClass, RetentionClasses, TenancyLink, UserMapping,
};
use crate::user::{ManagementUser, ObjectUser, SecretKey, SwiftGroup, UserTag};
use objectscale_client::{client, iam, provisioning, replication, tenancy, user};
use pyo3::prelude::*;
use pyo3::{exceptions, PyResult};

// ManagementClient manages ObjectScale resources with the ObjectScale management REST APIs.
#[pyclass]
pub(crate) struct ManagementClient {
    management_client: client::ManagementClient,
}

#[pymethods]
impl ManagementClient {
    /// Build a new ManagementClient.
    ///
    #[new]
    fn new(
        endpoint: &str,
        username: &str,
        password: &str,
        insecure: bool,
    ) -> PyResult<ManagementClient> {
        let result = client::ManagementClient::new(endpoint, username, password, insecure);
        match result {
            Ok(management_client) => Ok(Self { management_client }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates a new IAM User.
    ///
    /// user: IAM User to create
    ///
    pub fn create_user(&mut self, user: &User) -> PyResult<User> {
        let user = iam::User::from(user.clone());
        let result = self.management_client.create_user(user);
        match result {
            Ok(user) => Ok(User::from(user)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Retrieve IAM user.
    ///
    /// name: The name of the user to retrieve.
    /// namespace: ECS namespace IAM entity belongs to
    ///
    pub fn get_user(&mut self, name: &str, namespace: &str) -> PyResult<User> {
        let result = self.management_client.get_user(name, namespace);
        match result {
            Ok(user) => Ok(User::from(user)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates an IAM user.
    ///
    /// user: IAM User to be updated
    ///
    pub fn update_user(&mut self, user: &User) -> PyResult<bool> {
        let user = iam::User::from(user.clone());
        let result = self.management_client.update_user(user);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete specified IAM User.
    ///
    /// user_name: The name of the user to delete. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn delete_user(&mut self, user_name: &str, namespace: &str) -> PyResult<()> {
        let result = self.management_client.delete_user(user_name, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists the IAM users.
    ///
    /// namespace: Namespace of users(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn list_users(&mut self, namespace: &str) -> PyResult<Vec<User>> {
        let result = self.management_client.list_users(namespace);
        match result {
            Ok(users) => Ok(users.into_iter().map(User::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Attaches the specified managed policy to the specified user.
    ///
    /// user_policy_attachment: UserPolicyAttachment to create
    ///
    /// PS: attach the same policy would throw error
    ///
    pub fn create_user_policy_attachment(
        &mut self,
        user_policy_attachment: &UserPolicyAttachment,
    ) -> PyResult<UserPolicyAttachment> {
        let user_policy_attachment =
            iam::UserPolicyAttachment::from(user_policy_attachment.clone());
        let result = self
            .management_client
            .create_user_policy_attachment(user_policy_attachment);
        match result {
            Ok(user_policy_attachment) => Ok(UserPolicyAttachment::from(user_policy_attachment)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Remove the specified managed policy attached to the specified user.
    ///
    /// user_policy_attachment: UserPolicyAttachment to delete.
    ///
    pub fn delete_user_policy_attachment(
        &mut self,
        user_policy_attachment: &UserPolicyAttachment,
    ) -> PyResult<()> {
        let user_policy_attachment =
            iam::UserPolicyAttachment::from(user_policy_attachment.clone());
        let result = self
            .management_client
            .delete_user_policy_attachment(user_policy_attachment);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists all managed policies that are attached to the specified IAM user.
    ///
    /// user_name: The name of the user to list attached policies for. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn list_user_policy_attachments(
        &mut self,
        user_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<UserPolicyAttachment>> {
        let result = self
            .management_client
            .list_user_policy_attachments(user_name, namespace);
        match result {
            Ok(user_policy_attachments) => Ok(user_policy_attachments
                .into_iter()
                .map(UserPolicyAttachment::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates AccessKey for user.
    ///
    /// access_key: AccessKey to create
    ///
    pub fn create_access_key(&mut self, access_key: &AccessKey) -> PyResult<AccessKey> {
        let access_key = iam::AccessKey::from(access_key.clone());
        let result = self.management_client.create_access_key(access_key);
        match result {
            Ok(access_key) => Ok(AccessKey::from(access_key)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates AccessKey for user.
    ///
    /// access_key: AccessKey to update
    ///
    pub fn update_access_key(&mut self, access_key: &AccessKey) -> PyResult<bool> {
        let access_key = iam::AccessKey::from(access_key.clone());
        let result = self.management_client.update_access_key(access_key);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Deletes the access key pair associated with the specified IAM user.
    ///
    /// access_key_id: The ID of the access key you want to delete. Cannot be empty.
    /// user_name: Name of the user to delete accesskeys. Cannot be empty.
    /// namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
    ///
    pub fn delete_access_key(
        &mut self,
        access_key_id: &str,
        user_name: &str,
        namespace: &str,
    ) -> PyResult<()> {
        let result = self
            .management_client
            .delete_access_key(access_key_id, user_name, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Returns information about the access key IDs associated with the specified IAM user.
    ///
    /// user_name: Name of the user to list accesskeys. Cannot be empty.
    /// namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
    ///
    pub fn list_access_keys(
        &mut self,
        user_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<AccessKey>> {
        let result = self
            .management_client
            .list_access_keys(user_name, namespace);
        match result {
            Ok(access_keys) => Ok(access_keys.into_iter().map(AccessKey::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Create a new Managed Policy.
    ///
    /// policy: IAM Policy to create
    ///
    pub fn create_policy(&mut self, policy: &Policy) -> PyResult<Policy> {
        let policy = iam::Policy::from(policy.clone());
        let result = self.management_client.create_policy(policy);
        match result {
            Ok(policy) => Ok(Policy::from(policy)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Retrieve information about the specified Managed Policy.
    ///
    /// policy_arn: Arn of the policy to retrieve. Cannot be empty.
    /// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
    ///
    pub fn get_policy(&mut self, policy_arn: &str, namespace: &str) -> PyResult<Policy> {
        let result = self.management_client.get_policy(policy_arn, namespace);
        match result {
            Ok(policy) => Ok(Policy::from(policy)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Create a new version of the specified managed policy.
    ///
    /// policy_arn: Arn of the policy to retrieve. Cannot be empty.
    /// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
    ///
    pub fn update_policy(&mut self, policy: &Policy) -> PyResult<bool> {
        let policy = iam::Policy::from(policy.clone());
        let result = self.management_client.update_policy(policy);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete the specified Managed Policy.
    ///
    /// policy_arn: Arn of the policy to delete. Cannot be empty.
    /// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
    ///
    pub fn delete_policy(&mut self, policy_arn: &str, namespace: &str) -> PyResult<()> {
        let result = self.management_client.delete_policy(policy_arn, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists IAM Managed Policies.
    ///
    /// namespace: Namespace of the policies(id of the account policies belongs to). Cannot be empty.
    ///
    pub fn list_policies(&mut self, namespace: &str) -> PyResult<Vec<Policy>> {
        let result = self.management_client.list_policies(namespace);
        match result {
            Ok(policys) => Ok(policys.into_iter().map(Policy::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates a new IAM Group.
    ///
    /// group: IAM Group to create
    ///
    pub fn create_group(&mut self, group: &Group) -> PyResult<Group> {
        let group = iam::Group::from(group.clone());
        let result = self.management_client.create_group(group);
        match result {
            Ok(group) => Ok(Group::from(group)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Returns the information about the specified IAM Group.
    ///
    /// group_name: The name of the group to retrieve. Cannot be empty.
    /// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
    ///
    pub fn get_group(&mut self, group_name: &str, namespace: &str) -> PyResult<Group> {
        let result = self.management_client.get_group(group_name, namespace);
        match result {
            Ok(group) => Ok(Group::from(group)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete specified IAM User.
    ///
    /// group_name: The name of the group to delete. Cannot be empty.
    /// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
    ///
    pub fn delete_group(&mut self, group_name: &str, namespace: &str) -> PyResult<()> {
        let result = self.management_client.delete_group(group_name, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists the IAM groups.
    ///
    /// namespace: Namespace of groups(id of the account groups belongs to). Cannot be empty.
    ///
    pub fn list_groups(&mut self, namespace: &str) -> PyResult<Vec<Group>> {
        let result = self.management_client.list_groups(namespace);
        match result {
            Ok(groups) => Ok(groups.into_iter().map(Group::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Attaches the specified managed policy to the specified group.
    ///
    /// group_policy_attachment: GroupPolicyAttachment to create
    ///
    pub fn create_group_policy_attachment(
        &mut self,
        group_policy_attachment: &GroupPolicyAttachment,
    ) -> PyResult<GroupPolicyAttachment> {
        let group_policy_attachment =
            iam::GroupPolicyAttachment::from(group_policy_attachment.clone());
        let result = self
            .management_client
            .create_group_policy_attachment(group_policy_attachment);
        match result {
            Ok(group_policy_attachment) => Ok(GroupPolicyAttachment::from(group_policy_attachment)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Remove the specified managed policy attached to the specified group.
    ///
    /// group_policy_attachment: GroupPolicyAttachment to delete.
    ///
    pub fn delete_group_policy_attachment(
        &mut self,
        group_policy_attachment: &GroupPolicyAttachment,
    ) -> PyResult<()> {
        let group_policy_attachment =
            iam::GroupPolicyAttachment::from(group_policy_attachment.clone());
        let result = self
            .management_client
            .delete_group_policy_attachment(group_policy_attachment);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists all managed policies that are attached to the specified IAM Group.
    ///
    /// group_name: The name of the group to list attached policies for. Cannot be empty.
    /// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
    ///
    pub fn list_group_policy_attachments(
        &mut self,
        group_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<GroupPolicyAttachment>> {
        let result = self
            .management_client
            .list_group_policy_attachments(group_name, namespace);
        match result {
            Ok(group_policy_attachments) => Ok(group_policy_attachments
                .into_iter()
                .map(GroupPolicyAttachment::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates a new IAM Role.
    ///
    /// role: IAM Role to create
    ///
    pub fn create_role(&mut self, role: &Role) -> PyResult<Role> {
        let role = iam::Role::from(role.clone());
        let result = self.management_client.create_role(role);
        match result {
            Ok(role) => Ok(Role::from(role)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Returns the information about the specified IAM Role.
    ///
    /// role_name: The name of the role to retrieve. Cannot be empty.
    /// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
    ///
    pub fn get_role(&mut self, role_name: &str, namespace: &str) -> PyResult<Role> {
        let result = self.management_client.get_role(role_name, namespace);
        match result {
            Ok(role) => Ok(Role::from(role)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates a new IAM Role.
    ///
    /// role: IAM Role to update
    ///
    pub fn update_role(&mut self, role: &Role) -> PyResult<bool> {
        let role = iam::Role::from(role.clone());
        let result = self.management_client.update_role(role);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete specified IAM Role.
    ///
    /// role_name: The name of the role to delete. Cannot be empty.
    /// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
    ///
    pub fn delete_role(&mut self, role_name: &str, namespace: &str) -> PyResult<()> {
        let result = self.management_client.delete_role(role_name, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists the IAM roles.
    ///
    /// namespace: Namespace of roles(id of the account roles belongs to). Cannot be empty.
    ///
    pub fn list_roles(&mut self, namespace: &str) -> PyResult<Vec<Role>> {
        let result = self.management_client.list_roles(namespace);
        match result {
            Ok(roles) => Ok(roles.into_iter().map(Role::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Attaches the specified managed policy to the specified role.
    ///
    /// role_policy_attachment: RolePolicyAttachment to create
    ///
    pub fn create_role_policy_attachment(
        &mut self,
        role_policy_attachment: &RolePolicyAttachment,
    ) -> PyResult<RolePolicyAttachment> {
        let role_policy_attachment =
            iam::RolePolicyAttachment::from(role_policy_attachment.clone());
        let result = self
            .management_client
            .create_role_policy_attachment(role_policy_attachment);
        match result {
            Ok(role_policy_attachment) => Ok(RolePolicyAttachment::from(role_policy_attachment)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Remove the specified managed policy attached to the specified role.
    ///
    /// role_policy_attachment: RolePolicyAttachment to delete.
    ///
    pub fn delete_role_policy_attachment(
        &mut self,
        role_policy_attachment: &RolePolicyAttachment,
    ) -> PyResult<()> {
        let role_policy_attachment =
            iam::RolePolicyAttachment::from(role_policy_attachment.clone());
        let result = self
            .management_client
            .delete_role_policy_attachment(role_policy_attachment);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists all managed policies that are attached to the specified IAM Role.
    ///
    /// role_name: The name of the role to list attached policies for. Cannot be empty.
    /// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
    ///
    pub fn list_role_policy_attachments(
        &mut self,
        role_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<RolePolicyAttachment>> {
        let result = self
            .management_client
            .list_role_policy_attachments(role_name, namespace);
        match result {
            Ok(role_policy_attachments) => Ok(role_policy_attachments
                .into_iter()
                .map(RolePolicyAttachment::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists all IAM users, groups, and roles that the specified managed policy is attached to.
    ///
    /// policy_arn: Arn of the policy to list entities for. Cannot be empty.
    /// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
    /// entity_filter: The entity type to use for filtering the results. Valid values: User, Role, Group.
    /// usage_filter: The policy usage method to use for filtering the results. Valid values: PermissionsPolicy, PermissionsBoundary.
    ///
    pub fn get_entities_for_policy(
        &mut self,
        policy_arn: &str,
        namespace: &str,
        entity_filter: &str,
        usage_filter: &str,
    ) -> PyResult<EntitiesForPolicy> {
        let result = self.management_client.get_entities_for_policy(
            policy_arn,
            namespace,
            entity_filter,
            usage_filter,
        );
        match result {
            Ok(entities_for_policy) => Ok(EntitiesForPolicy::from(entities_for_policy)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Adds the specified user to the specified group.
    ///
    /// user_group_membership: UserGroupMembership to create.
    ///
    pub fn create_user_group_membership(
        &mut self,
        user_group_membership: &UserGroupMembership,
    ) -> PyResult<UserGroupMembership> {
        let user_group_membership = iam::UserGroupMembership::from(user_group_membership.clone());
        let result = self
            .management_client
            .create_user_group_membership(user_group_membership);
        match result {
            Ok(user_group_membership) => Ok(UserGroupMembership::from(user_group_membership)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Removes the specified user from the specified group.
    ///
    /// user_group_membership: GroupPolicyAttachment to delete.
    ///
    pub fn delete_user_group_membership(
        &mut self,
        user_group_membership: &UserGroupMembership,
    ) -> PyResult<()> {
        let user_group_membership = iam::UserGroupMembership::from(user_group_membership.clone());
        let result = self
            .management_client
            .delete_user_group_membership(user_group_membership);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists the IAM groups that the specified IAM user belongs to.
    ///
    /// user_name: The name of the user to list group membership for. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn list_user_group_memberships_by_user(
        &mut self,
        user_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<UserGroupMembership>> {
        let result = self
            .management_client
            .list_user_group_memberships_by_user(user_name, namespace);
        match result {
            Ok(user_group_memberships) => Ok(user_group_memberships
                .into_iter()
                .map(UserGroupMembership::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Create SAML Identity Provider
    ///
    /// provider: SAML provider to create
    ///
    pub fn create_saml_provider(&mut self, provider: &SamlProvider) -> PyResult<SamlProvider> {
        let provider = iam::SamlProvider::from(provider.clone());
        let result = self.management_client.create_saml_provider(provider);
        match result {
            Ok(saml_provider) => Ok(SamlProvider::from(saml_provider)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Retrieve the SAML IdP document.
    ///
    /// arn: The name of the provider to retrieve.
    /// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
    ///
    pub fn get_saml_provider(&mut self, arn: &str, namespace: &str) -> PyResult<SamlProvider> {
        let result = self.management_client.get_saml_provider(arn, namespace);
        match result {
            Ok(saml_provider) => Ok(SamlProvider::from(saml_provider)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update the SAML Identity Provider.
    ///
    /// role: SAML Identity Provider to update
    ///
    pub fn update_saml_provider(&mut self, provider: &SamlProvider) -> PyResult<bool> {
        let provider = iam::SamlProvider::from(provider.clone());
        let result = self.management_client.update_saml_provider(provider);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete the SAML Identity Provider.
    ///
    /// arn: The ARN of the provider to delete.
    /// namespace: ECS namespace IAM entity belongs to
    ///
    pub fn delete_saml_provider(&mut self, arn: &str, namespace: &str) -> PyResult<()> {
        let result = self.management_client.delete_saml_provider(arn, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// List the SAML Identity Providers.
    ///
    /// namespace: ECS namespace IAM entity belongs to
    ///
    pub fn list_saml_providers(&mut self, namespace: &str) -> PyResult<Vec<SamlProvider>> {
        let result = self.management_client.list_saml_providers(namespace);
        match result {
            Ok(saml_providers) => Ok(saml_providers.into_iter().map(SamlProvider::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists the IAM users that the specified IAM group contains.
    ///
    /// group_name: The name of the group to list contained users for. Cannot be empty.
    /// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
    ///
    pub fn list_user_group_memberships_by_group(
        &mut self,
        group_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<UserGroupMembership>> {
        let result = self
            .management_client
            .list_user_group_memberships_by_group(group_name, namespace);
        match result {
            Ok(user_group_memberships) => Ok(user_group_memberships
                .into_iter()
                .map(UserGroupMembership::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Add Inline Policy for IAM User.
    ///
    /// user_inline_policy: UserInlinePolicy to create
    ///
    pub fn create_user_inline_policy(
        &mut self,
        user_inline_policy: &UserInlinePolicy,
    ) -> PyResult<UserInlinePolicy> {
        let user_inline_policy = iam::UserInlinePolicy::from(user_inline_policy.clone());
        let result = self
            .management_client
            .create_user_inline_policy(user_inline_policy);
        match result {
            Ok(user_inline_policy) => Ok(UserInlinePolicy::from(user_inline_policy)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Get specific inlinePolicy for IAM User.
    ///
    /// user_name: Name of the user
    /// policy_name: Name of the policy
    /// namespace: Namespace of the user
    ///
    pub fn get_user_inline_policy(
        &mut self,
        user_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> PyResult<UserInlinePolicy> {
        let result =
            self.management_client
                .get_user_inline_policy(user_name, policy_name, namespace);
        match result {
            Ok(user_inline_policy) => Ok(UserInlinePolicy::from(user_inline_policy)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update Inline Policy for IAM User.
    ///
    /// user_inline_policy: UserInlinePolicy to update
    ///
    pub fn update_user_inline_policy(
        &mut self,
        user_inline_policy: &UserInlinePolicy,
    ) -> PyResult<bool> {
        let user_inline_policy = iam::UserInlinePolicy::from(user_inline_policy.clone());
        let result = self
            .management_client
            .update_user_inline_policy(user_inline_policy);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete specific inlinePolicy for IAM User.
    ///
    /// user_name: Name of the user
    /// policy_name: Name of the policy
    /// namespace: Namespace of the user
    ///
    pub fn delete_user_inline_policy(
        &mut self,
        user_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> PyResult<()> {
        let result =
            self.management_client
                .delete_user_inline_policy(user_name, policy_name, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists all user inline policies.
    ///
    pub fn list_user_inline_policies(
        &mut self,
        user_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<UserInlinePolicy>> {
        let result = self
            .management_client
            .list_user_inline_policies(user_name, namespace);
        match result {
            Ok(user_inline_policys) => Ok(user_inline_policys
                .into_iter()
                .map(UserInlinePolicy::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Add Inline Policy for IAM Group.
    ///
    /// group_inline_policy: GroupInlinePolicy to create
    ///
    pub fn create_group_inline_policy(
        &mut self,
        group_inline_policy: &GroupInlinePolicy,
    ) -> PyResult<GroupInlinePolicy> {
        let group_inline_policy = iam::GroupInlinePolicy::from(group_inline_policy.clone());
        let result = self
            .management_client
            .create_group_inline_policy(group_inline_policy);
        match result {
            Ok(group_inline_policy) => Ok(GroupInlinePolicy::from(group_inline_policy)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Get specific inlinePolicy for IAM Group.
    ///
    /// group_name: Name of the group
    /// policy_name: Name of the policy
    /// namespace: Namespace of the group
    ///
    pub fn get_group_inline_policy(
        &mut self,
        group_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> PyResult<GroupInlinePolicy> {
        let result =
            self.management_client
                .get_group_inline_policy(group_name, policy_name, namespace);
        match result {
            Ok(group_inline_policy) => Ok(GroupInlinePolicy::from(group_inline_policy)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update Inline Policy for IAM group.
    ///
    /// group_inline_policy: GroupInlinePolicy to update
    ///
    pub fn update_group_inline_policy(
        &mut self,
        group_inline_policy: &GroupInlinePolicy,
    ) -> PyResult<bool> {
        let group_inline_policy = iam::GroupInlinePolicy::from(group_inline_policy.clone());
        let result = self
            .management_client
            .update_group_inline_policy(group_inline_policy);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete specific inlinePolicy for IAM User.
    ///
    /// group_name: Name of the group
    /// policy_name: Name of the policy
    /// namespace: Namespace of the group
    ///
    pub fn delete_group_inline_policy(
        &mut self,
        group_name: &str,
        policy_name: &str,
        namespace: &str,
    ) -> PyResult<()> {
        let result =
            self.management_client
                .delete_group_inline_policy(group_name, policy_name, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists all group inline policies.
    ///
    pub fn list_group_inline_policies(
        &mut self,
        group_name: &str,
        namespace: &str,
    ) -> PyResult<Vec<GroupInlinePolicy>> {
        let result = self
            .management_client
            .list_group_inline_policies(group_name, namespace);
        match result {
            Ok(group_inline_policys) => Ok(group_inline_policys
                .into_iter()
                .map(GroupInlinePolicy::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets the list of buckets for the specified namespace.
    ///
    /// namespace: Namespace for which buckets should be listed. Cannot be empty.
    /// name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
    ///
    pub fn list_buckets(&mut self, namespace: &str, name_prefix: &str) -> PyResult<Vec<Bucket>> {
        let result = self.management_client.list_buckets(namespace, name_prefix);
        match result {
            Ok(buckets) => Ok(buckets.into_iter().map(Bucket::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Create an bucket.
    ///
    /// bucket: Bucket to create.
    ///
    pub fn create_bucket(&mut self, bucket: &Bucket) -> PyResult<Bucket> {
        let bucket = provisioning::Bucket::from(bucket.clone());
        let result = self.management_client.create_bucket(bucket);
        match result {
            Ok(bucket) => Ok(Bucket::from(bucket)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets bucket information for the specified bucket.
    ///
    /// name: Bucket name for which information will be retrieved. Cannot be empty.
    /// namespace: Namespace associated. Cannot be empty.
    ///
    pub fn get_bucket(&mut self, name: &str, namespace: &str) -> PyResult<Bucket> {
        let result = self.management_client.get_bucket(name, namespace);
        match result {
            Ok(bucket) => Ok(Bucket::from(bucket)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update an bucket.
    ///
    /// bucket: Bucket to update.
    ///
    pub fn update_bucket(&mut self, bucket: &Bucket) -> PyResult<bool> {
        let bucket = provisioning::Bucket::from(bucket.clone());
        let result = self.management_client.update_bucket(bucket);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Deletes the specified bucket.
    ///
    /// name: Bucket name to be deleted. Cannot be empty.
    /// namespace: Namespace associated. Cannot be empty.
    /// emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
    ///
    pub fn delete_bucket(
        &mut self,
        name: &str,
        namespace: &str,
        empty_bucket: bool,
    ) -> PyResult<()> {
        let result = self
            .management_client
            .delete_bucket(name, namespace, empty_bucket);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates a namespace with the given details.
    ///
    /// namespace: Namespace to create
    ///
    pub fn create_namespace(&mut self, namespace: &Namespace) -> PyResult<Namespace> {
        let namespace = tenancy::Namespace::from(namespace.clone());
        let result = self.management_client.create_namespace(namespace);
        match result {
            Ok(namespace) => Ok(Namespace::from(namespace)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets the details for the given namespace.
    ///
    /// id: Namespace identifier for which details needs to be retrieved.
    ///
    pub fn get_namespace(&mut self, id: &str) -> PyResult<Namespace> {
        let result = self.management_client.get_namespace(id);
        match result {
            Ok(namespace) => Ok(Namespace::from(namespace)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update a namespace with the given details.
    ///
    /// namespace: Namespace to be updated
    ///
    pub fn update_namespace(&mut self, namespace: &Namespace) -> PyResult<bool> {
        let namespace = tenancy::Namespace::from(namespace.clone());
        let result = self.management_client.update_namespace(namespace);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Deactivates and deletes the given namespace and all associated user mappings.
    ///
    /// id: An active namespace identifier which needs to be deactivated/deleted
    ///
    pub fn delete_namespace(&mut self, id: &str) -> PyResult<()> {
        let result = self.management_client.delete_namespace(id);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets the list of all configured namespaces.
    ///
    /// name_prefix: Case sensitive prefix of the Namespace name with a wild card(*) Ex : any_prefix_string*.
    ///
    pub fn list_namespaces(&mut self, name_prefix: &str) -> PyResult<Vec<Namespace>> {
        let result = self.management_client.list_namespaces(name_prefix);
        match result {
            Ok(namespaces) => Ok(namespaces.into_iter().map(Namespace::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates local users for the VDC.
    ///
    /// user: ManagementUser to create
    ///
    pub fn create_management_user(&mut self, user: &ManagementUser) -> PyResult<ManagementUser> {
        let user = user::ManagementUser::from(user.clone());
        let result = self.management_client.create_management_user(user);
        match result {
            Ok(management_user) => Ok(ManagementUser::from(management_user)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets details for the specified local management user.
    ///
    /// id: User identifier for which local user information needs to be retrieved
    ///
    pub fn get_management_user(&mut self, id: &str) -> PyResult<ManagementUser> {
        let result = self.management_client.get_management_user(id);
        match result {
            Ok(management_user) => Ok(ManagementUser::from(management_user)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates user details for the specified local management user.
    ///
    /// user: ManagementUser to be updated
    ///
    pub fn update_management_user(&mut self, user: &ManagementUser) -> PyResult<bool> {
        let user = user::ManagementUser::from(user.clone());
        let result = self.management_client.update_management_user(user);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Deletes local management user information for the specified user identifier.
    ///
    /// id: User identifier for which local user information needs to be deleted.
    ///
    pub fn delete_management_user(&mut self, id: &str) -> PyResult<()> {
        let result = self.management_client.delete_management_user(id);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets all configured local management users.
    ///
    pub fn list_management_users(&mut self) -> PyResult<Vec<ManagementUser>> {
        let result = self.management_client.list_management_users();
        match result {
            Ok(management_users) => Ok(management_users
                .into_iter()
                .map(ManagementUser::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates a user for a specified namespace.
    ///
    /// user: ObjectUser to create
    ///
    pub fn create_object_user(&mut self, user: &ObjectUser) -> PyResult<ObjectUser> {
        let user = user::ObjectUser::from(user.clone());
        let result = self.management_client.create_object_user(user);
        match result {
            Ok(object_user) => Ok(ObjectUser::from(object_user)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets user details for the specified user belong to the specified namespace.
    ///
    /// name: Valid user identifier
    /// namespace: The namespace to which user belong
    ///
    pub fn get_object_user(&mut self, name: &str, namespace: &str) -> PyResult<ObjectUser> {
        let result = self.management_client.get_object_user(name, namespace);
        match result {
            Ok(object_user) => Ok(ObjectUser::from(object_user)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates user details for the specified object user.
    ///
    /// user: ObjectUser to be updated
    ///
    pub fn update_object_user(&mut self, user: &ObjectUser) -> PyResult<bool> {
        let user = user::ObjectUser::from(user.clone());
        let result = self.management_client.update_object_user(user);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Deletes the specified user and its secret keys.
    ///
    /// name: User to be deleted.
    /// namespace: Namespace identifier to associate with the user
    ///
    pub fn delete_object_user(&mut self, name: &str, namespace: &str) -> PyResult<()> {
        let result = self.management_client.delete_object_user(name, namespace);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets identifiers for all configured users.
    ///
    pub fn list_object_users(&mut self) -> PyResult<Vec<ObjectUser>> {
        let result = self.management_client.list_object_users();
        match result {
            Ok(object_users) => Ok(object_users.into_iter().map(ObjectUser::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Get the certificate chain being used by ECS
    ///
    pub fn get_vdc_keystore(&mut self) -> PyResult<VdcKeystore> {
        let result = self.management_client.get_vdc_keystore();
        match result {
            Ok(vdc_keystore) => Ok(VdcKeystore::from(vdc_keystore)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Set the certificate chain being used by ECS.
    ///
    /// keystore: VdcKeystore to be updated
    ///
    pub fn update_vdc_keystore(&mut self, keystore: &VdcKeystore) -> PyResult<bool> {
        let keystore = provisioning::VdcKeystore::from(keystore.clone());
        let result = self.management_client.update_vdc_keystore(keystore);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Create a VDC with the specified details.
    ///
    /// vdc: VDC to be created
    ///
    pub fn create_vdc(&mut self, vdc: &Vdc) -> PyResult<Vdc> {
        let vdc = provisioning::Vdc::from(vdc.clone());
        let result = self.management_client.create_vdc(vdc);
        match result {
            Ok(vdc) => Ok(Vdc::from(vdc)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets the details for a VDC the identify of which is specified by its name.
    ///
    /// name: VDC name for which VDC Information is to be retrieved
    ///
    pub fn get_vdc(&mut self, name: &str) -> PyResult<Vdc> {
        let result = self.management_client.get_vdc(name);
        match result {
            Ok(vdc) => Ok(Vdc::from(vdc)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update VDC info
    ///
    /// vdc: VDC to be updated
    ///
    pub fn update_vdc(&mut self, vdc: &Vdc) -> PyResult<bool> {
        let vdc = provisioning::Vdc::from(vdc.clone());
        let result = self.management_client.update_vdc(vdc);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Deactivates and deletes a VDC.
    ///
    /// id: VDC identifier for which VDC Information needs to be deleted
    ///
    pub fn delete_vdc(&mut self, id: &str) -> PyResult<()> {
        let result = self.management_client.delete_vdc(id);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets all details of all configured VDCs.
    ///
    pub fn list_vdcs(&mut self) -> PyResult<Vec<Vdc>> {
        let result = self.management_client.list_vdcs();
        match result {
            Ok(vdcs) => Ok(vdcs.into_iter().map(Vdc::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Create a storage pool with the specified details.
    ///
    /// sp: Storage pool to be created
    ///
    pub fn create_storage_pool(&mut self, sp: &StoragePool) -> PyResult<StoragePool> {
        let sp = provisioning::StoragePool::from(sp.clone());
        let result = self.management_client.create_storage_pool(sp);
        match result {
            Ok(storage_pool) => Ok(StoragePool::from(storage_pool)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets the details for the specified storage pool.
    ///
    /// id: Storage pool identifier to be retrieved
    ///
    pub fn get_storage_pool(&mut self, id: &str) -> PyResult<StoragePool> {
        let result = self.management_client.get_storage_pool(id);
        match result {
            Ok(storage_pool) => Ok(StoragePool::from(storage_pool)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates storage pool for the specified identifier..
    ///
    /// sp: Storage pool to be updated
    ///
    pub fn update_storage_pool(&mut self, sp: &StoragePool) -> PyResult<bool> {
        let sp = provisioning::StoragePool::from(sp.clone());
        let result = self.management_client.update_storage_pool(sp);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets a list of storage pools from the local VDC.
    ///
    pub fn list_storage_pools(&mut self) -> PyResult<Vec<StoragePool>> {
        let result = self.management_client.list_storage_pools();
        match result {
            Ok(storage_pools) => Ok(storage_pools.into_iter().map(StoragePool::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates a replication group that includes the specified storage pools
    ///
    /// rg: ReplicationGroup to create
    ///
    pub fn create_replication_group(
        &mut self,
        rg: &ReplicationGroup,
    ) -> PyResult<ReplicationGroup> {
        let rg = replication::ReplicationGroup::from(rg.clone());
        let result = self.management_client.create_replication_group(rg);
        match result {
            Ok(replication_group) => Ok(ReplicationGroup::from(replication_group)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets the details for the specified replication group.
    ///
    /// id: Replication group identifier for which details needs to be retrieved
    ///
    pub fn get_replication_group(&mut self, id: &str) -> PyResult<ReplicationGroup> {
        let result = self.management_client.get_replication_group(id);
        match result {
            Ok(replication_group) => Ok(ReplicationGroup::from(replication_group)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates the name and description for a replication group.
    ///
    /// rg: Replication group which details needs to be updated
    ///
    pub fn update_replication_group(&mut self, rg: &ReplicationGroup) -> PyResult<bool> {
        let rg = replication::ReplicationGroup::from(rg.clone());
        let result = self.management_client.update_replication_group(rg);
        match result {
            Ok(state) => Ok(state),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Lists all configured replication groups.
    ///
    pub fn list_replication_groups(&mut self) -> PyResult<Vec<ReplicationGroup>> {
        let result = self.management_client.list_replication_groups();
        match result {
            Ok(replication_groups) => Ok(replication_groups
                .into_iter()
                .map(ReplicationGroup::from)
                .collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }
}
