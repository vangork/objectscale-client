//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

//! Applications should use create ManagementClient to manage ObjectScale resources.
//!

use crate::iam::{
    AccessKey, EntitiesForPolicy, Group, GroupInlinePolicy, GroupPolicyAttachment, Policy, Role,
    RolePolicyAttachment, SamlProvider, User, UserGroupMembership, UserInlinePolicy,
    UserPolicyAttachment,
};
use crate::provisioning::{Bucket, StoragePool, Vdc, VdcKeystore};
use crate::replication::ReplicationGroup;
use crate::response::get_content_text;
use crate::tenancy::Namespace;
use crate::user::{ManagementUser, ObjectUser};
use anyhow::{anyhow, bail, Context as _, Result};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const AUTH_HEADER_KEY: &str = "X-SDS-AUTH-TOKEN";

/// ManagementClient manages ObjectScale resources with the ObjectScale management REST APIs.
///
/// # Examples
/// ```no_run
/// use objectscale_client::client::ManagementClient;
///
/// fn main() {
///     let endpoint = "https://192.168.1.1:443";
///     let username = "user";
///     let password = "pass";
///     let insecure = false;
///     let mut client = ManagementClient::new(endpoint, username, password, insecure).expect("management client");
///     let vdcs = client.list_vdcs().expect("list vdcs");
///     println!("List vdcs: {:?}", vdcs);
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ManagementClient {
    pub(crate) http_client: Client,
    pub(crate) endpoint: Url,
    username: String,
    password: String,

    pub(crate) access_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    pub user: String,
}

impl Drop for ManagementClient {
    fn drop(&mut self) {
        self.log_out().expect("log out");
    }
}

impl ManagementClient {
    /// Build a new ManagementClient.
    ///
    pub fn new(endpoint: &str, username: &str, password: &str, insecure: bool) -> Result<Self> {
        let timeout = Duration::new(5, 0);
        let http_client = ClientBuilder::new()
            .timeout(timeout)
            .danger_accept_invalid_certs(insecure)
            .use_rustls_tls()
            .build()
            .expect("build client");
        Ok(Self {
            http_client,
            endpoint: Url::parse(endpoint)?,
            username: username.to_string(),
            password: password.to_string(),

            access_token: None,
            expires_in: None,
        })
    }

    fn login(&mut self) -> Result<()> {
        let request_url = format!("{}login", self.endpoint);
        let resp = self
            .http_client
            .get(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .basic_auth(&self.username, Some(&self.password))
            .send()?;

        let status = resp.status();
        if status.is_client_error() || status.is_server_error() {
            bail!("Login failed: {}", resp.text()?);
        }

        let token = resp
            .headers()
            .get("X-SDS-AUTH-TOKEN")
            .ok_or_else(|| anyhow!("X-SDS-AUTH-TOKEN header not found"))?;
        self.access_token = Some(token.to_str()?.to_string());
        let obtain_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let age = resp
            .headers()
            .get("X-SDS-AUTH-MAX-AGE")
            .ok_or_else(|| anyhow!("X-SDS-AUTH-MAX-AGE header not found"))?;
        let age = age.to_str()?.parse::<u64>()?;
        self.expires_in = Some(age + obtain_time);

        let text = resp.text()?;
        let _: AuthResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise login AuthResponse. Body was: \"{}\"",
                text
            )
        })?;

        Ok(())
    }

    fn log_out(&mut self) -> Result<()> {
        if self.access_token.is_none() {
            return Ok(());
        }
        let request_url = format!("{}logout", self.endpoint);
        let resp = self
            .http_client
            .get(request_url)
            .header(AUTH_HEADER_KEY, self.access_token.as_ref().unwrap())
            .header(ACCEPT, "application/json")
            .basic_auth(&self.username, Some(&self.password))
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to log out")?;
        let _: AuthResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise logout AuthResponse. Body was: \"{}\"",
                text
            )
        })?;
        self.access_token = None;
        self.expires_in = None;
        Ok(())
    }

    fn auth(&mut self) -> Result<()> {
        if self.access_token.is_none() {
            self.login()?;
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if self.expires_in.unwrap() > now {
            } else {
                self.login()?;
            }
        }
        Ok(())
    }

    /// Creates a new IAM User.
    ///
    /// user: IAM User to create
    ///
    pub fn create_user(&mut self, user: User) -> Result<User> {
        self.auth()?;
        User::create(self, &user)?;
        User::get(self, &user.user_name, &user.namespace)
    }

    /// Retrieve IAM user.
    ///
    /// name: The name of the user to retrieve.
    /// namespace: ECS namespace IAM entity belongs to
    ///
    pub fn get_user(&mut self, name: &str, namespace: &str) -> Result<User> {
        self.auth()?;
        User::get(self, name, namespace)
    }

    /// Updates an IAM user.
    ///
    /// user: IAM User to be updated
    ///
    pub fn update_user(&mut self, user: User) -> Result<bool> {
        self.auth()?;
        User::update(self, &user)
    }

    /// Delete specified IAM User.
    ///
    /// user_name: The name of the user to delete. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn delete_user(&mut self, user_name: &str, namespace: &str) -> Result<()> {
        self.auth()?;
        User::delete(self, user_name, namespace)
    }

    /// Lists the IAM users.
    ///
    /// namespace: Namespace of users(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn list_users(&mut self, namespace: &str) -> Result<Vec<User>> {
        self.auth()?;
        User::list(self, namespace)
    }

    /// Attaches the specified managed policy to the specified user.
    ///
    /// user_policy_attachment: UserPolicyAttachment to create
    ///
    /// PS: attach the same policy would throw error
    ///
    pub fn create_user_policy_attachment(
        &mut self,
        user_policy_attachment: UserPolicyAttachment,
    ) -> Result<UserPolicyAttachment> {
        self.auth()?;
        UserPolicyAttachment::create(self, &user_policy_attachment)?;
        let list = UserPolicyAttachment::list(
            self,
            &user_policy_attachment.user_name,
            &user_policy_attachment.namespace,
        )?;
        list.into_iter()
            .find(|attachment| attachment.policy_arn == user_policy_attachment.policy_arn)
            .ok_or_else(|| anyhow!("Failed to locate the new created user policy attachment"))
    }

    /// Remove the specified managed policy attached to the specified user.
    ///
    /// user_policy_attachment: UserPolicyAttachment to delete.
    ///
    pub fn delete_user_policy_attachment(
        &mut self,
        user_policy_attachment: UserPolicyAttachment,
    ) -> Result<()> {
        self.auth()?;
        UserPolicyAttachment::delete(self, user_policy_attachment)
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
    ) -> Result<Vec<UserPolicyAttachment>> {
        self.auth()?;
        UserPolicyAttachment::list(self, user_name, namespace)
    }

    /// Creates AccessKey for user.
    ///
    /// access_key: AccessKey to create
    ///
    pub fn create_access_key(&mut self, access_key: AccessKey) -> Result<AccessKey> {
        self.auth()?;
        AccessKey::create(self, access_key)
    }

    /// Updates AccessKey for user.
    ///
    /// access_key: AccessKey to update
    ///
    pub fn update_access_key(&mut self, access_key: AccessKey) -> Result<bool> {
        self.auth()?;
        let access_keys = self.list_access_keys(&access_key.user_name, &access_key.namespace)?;
        let current_access_key = access_keys
            .into_iter()
            .find(|key| key.access_key_id == access_key.access_key_id)
            .ok_or(anyhow!("AccessKey not found"))?;
        if access_key.status != current_access_key.status {
            AccessKey::update(self, access_key.clone())?;
            Ok(true)
        } else {
            Ok(false)
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
    ) -> Result<()> {
        self.auth()?;
        AccessKey::delete(self, access_key_id, user_name, namespace)
    }

    /// Returns information about the access key IDs associated with the specified IAM user.
    ///
    /// user_name: Name of the user to list accesskeys. Cannot be empty.
    /// namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
    ///
    pub fn list_access_keys(&mut self, user_name: &str, namespace: &str) -> Result<Vec<AccessKey>> {
        self.auth()?;
        AccessKey::list(self, user_name, namespace)
    }

    /// Create a new Managed Policy.
    ///
    /// policy: IAM Policy to create
    ///
    pub fn create_policy(&mut self, policy: Policy) -> Result<Policy> {
        self.auth()?;
        let policy = Policy::create(self, policy)?;
        Policy::get(self, &policy.arn, &policy.namespace)
    }

    /// Retrieve information about the specified Managed Policy.
    ///
    /// policy_arn: Arn of the policy to retrieve. Cannot be empty.
    /// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
    ///
    pub fn get_policy(&mut self, policy_arn: &str, namespace: &str) -> Result<Policy> {
        self.auth()?;
        Policy::get(self, policy_arn, namespace)
    }

    /// Create a new version of the specified managed policy.
    ///
    /// policy_arn: Arn of the policy to retrieve. Cannot be empty.
    /// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
    ///
    pub fn update_policy(&mut self, policy: Policy) -> Result<bool> {
        self.auth()?;
        Policy::update(self, policy)
    }

    /// Delete the specified Managed Policy.
    ///
    /// policy_arn: Arn of the policy to delete. Cannot be empty.
    /// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
    ///
    pub fn delete_policy(&mut self, policy_arn: &str, namespace: &str) -> Result<()> {
        self.auth()?;
        Policy::delete(self, policy_arn, namespace)
    }

    /// Lists IAM Managed Policies.
    ///
    /// namespace: Namespace of the policies(id of the account policies belongs to). Cannot be empty.
    ///
    pub fn list_policies(&mut self, namespace: &str) -> Result<Vec<Policy>> {
        self.auth()?;
        Policy::list(self, namespace)
    }

    /// Creates a new IAM Group.
    ///
    /// group: IAM Group to create
    ///
    pub fn create_group(&mut self, group: Group) -> Result<Group> {
        self.auth()?;
        Group::create(self, group)
    }

    /// Returns the information about the specified IAM Group.
    ///
    /// group_name: The name of the group to retrieve. Cannot be empty.
    /// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
    ///
    pub fn get_group(&mut self, group_name: &str, namespace: &str) -> Result<Group> {
        self.auth()?;
        Group::get(self, group_name, namespace)
    }

    /// Delete specified IAM User.
    ///
    /// group_name: The name of the group to delete. Cannot be empty.
    /// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
    ///
    pub fn delete_group(&mut self, group_name: &str, namespace: &str) -> Result<()> {
        self.auth()?;
        Group::delete(self, group_name, namespace)
    }

    /// Lists the IAM groups.
    ///
    /// namespace: Namespace of groups(id of the account groups belongs to). Cannot be empty.
    ///
    pub fn list_groups(&mut self, namespace: &str) -> Result<Vec<Group>> {
        self.auth()?;
        Group::list(self, namespace)
    }

    /// Attaches the specified managed policy to the specified group.
    ///
    /// group_policy_attachment: GroupPolicyAttachment to create
    ///
    pub fn create_group_policy_attachment(
        &mut self,
        group_policy_attachment: GroupPolicyAttachment,
    ) -> Result<GroupPolicyAttachment> {
        self.auth()?;
        GroupPolicyAttachment::create(self, &group_policy_attachment)?;
        let list = GroupPolicyAttachment::list(
            self,
            &group_policy_attachment.group_name,
            &group_policy_attachment.namespace,
        )?;
        list.into_iter()
            .find(|attachment| attachment.policy_arn == group_policy_attachment.policy_arn)
            .ok_or_else(|| anyhow!("Failed to locate the new created group policy attachment"))
    }

    /// Remove the specified managed policy attached to the specified group.
    ///
    /// group_policy_attachment: GroupPolicyAttachment to delete.
    ///
    pub fn delete_group_policy_attachment(
        &mut self,
        group_policy_attachment: GroupPolicyAttachment,
    ) -> Result<()> {
        self.auth()?;
        GroupPolicyAttachment::delete(self, group_policy_attachment)
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
    ) -> Result<Vec<GroupPolicyAttachment>> {
        self.auth()?;
        GroupPolicyAttachment::list(self, group_name, namespace)
    }

    /// Creates a new IAM Role.
    ///
    /// role: IAM Role to create
    ///
    pub fn create_role(&mut self, role: Role) -> Result<Role> {
        self.auth()?;
        Role::create(self, role)
    }

    /// Returns the information about the specified IAM Role.
    ///
    /// role_name: The name of the role to retrieve. Cannot be empty.
    /// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
    ///
    pub fn get_role(&mut self, role_name: &str, namespace: &str) -> Result<Role> {
        self.auth()?;
        Role::get(self, role_name, namespace)
    }

    /// Updates a new IAM Role.
    ///
    /// role: IAM Role to update
    ///
    pub fn update_role(&mut self, role: Role) -> Result<bool> {
        self.auth()?;
        Role::update(self, &role)
    }

    /// Delete specified IAM Role.
    ///
    /// role_name: The name of the role to delete. Cannot be empty.
    /// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
    ///
    pub fn delete_role(&mut self, role_name: &str, namespace: &str) -> Result<()> {
        self.auth()?;
        Role::delete(self, role_name, namespace)
    }

    /// Lists the IAM roles.
    ///
    /// namespace: Namespace of roles(id of the account roles belongs to). Cannot be empty.
    ///
    pub fn list_roles(&mut self, namespace: &str) -> Result<Vec<Role>> {
        self.auth()?;
        Role::list(self, namespace)
    }

    /// Attaches the specified managed policy to the specified role.
    ///
    /// role_policy_attachment: RolePolicyAttachment to create
    ///
    pub fn create_role_policy_attachment(
        &mut self,
        role_policy_attachment: RolePolicyAttachment,
    ) -> Result<RolePolicyAttachment> {
        self.auth()?;
        RolePolicyAttachment::create(self, &role_policy_attachment)?;
        let list = RolePolicyAttachment::list(
            self,
            &role_policy_attachment.role_name,
            &role_policy_attachment.namespace,
        )?;
        list.into_iter()
            .find(|attachment| attachment.policy_arn == role_policy_attachment.policy_arn)
            .ok_or_else(|| anyhow!("Failed to locate the new created role policy attachment"))
    }

    /// Remove the specified managed policy attached to the specified role.
    ///
    /// role_policy_attachment: RolePolicyAttachment to delete.
    ///
    pub fn delete_role_policy_attachment(
        &mut self,
        role_policy_attachment: RolePolicyAttachment,
    ) -> Result<()> {
        self.auth()?;
        RolePolicyAttachment::delete(self, role_policy_attachment)
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
    ) -> Result<Vec<RolePolicyAttachment>> {
        self.auth()?;
        RolePolicyAttachment::list(self, role_name, namespace)
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
    ) -> Result<EntitiesForPolicy> {
        self.auth()?;
        EntitiesForPolicy::get(self, policy_arn, namespace, entity_filter, usage_filter)
    }

    /// Adds the specified user to the specified group.
    ///
    /// user_group_membership: UserGroupMembership to create.
    ///
    pub fn create_user_group_membership(
        &mut self,
        user_group_membership: UserGroupMembership,
    ) -> Result<UserGroupMembership> {
        self.auth()?;
        UserGroupMembership::create(self, user_group_membership)
    }

    /// Removes the specified user from the specified group.
    ///
    /// user_group_membership: GroupPolicyAttachment to delete.
    ///
    pub fn delete_user_group_membership(
        &mut self,
        user_group_membership: UserGroupMembership,
    ) -> Result<()> {
        self.auth()?;
        UserGroupMembership::delete(self, user_group_membership)
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
    ) -> Result<Vec<UserGroupMembership>> {
        self.auth()?;
        UserGroupMembership::list_by_user(self, user_name, namespace)
    }

    /// Create SAML Identity Provider
    ///
    /// provider: SAML provider to create
    ///
    pub fn create_saml_provider(&mut self, provider: SamlProvider) -> Result<SamlProvider> {
        self.auth()?;
        SamlProvider::create(self, provider)
    }

    /// Retrieve the SAML IdP document.
    ///
    /// arn: The name of the provider to retrieve.
    /// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
    ///
    pub fn get_saml_provider(&mut self, arn: &str, namespace: &str) -> Result<SamlProvider> {
        self.auth()?;
        SamlProvider::get(self, arn, namespace)
    }

    /// Update the SAML Identity Provider.
    ///
    /// role: SAML Identity Provider to update
    ///
    pub fn update_saml_provider(&mut self, provider: SamlProvider) -> Result<bool> {
        self.auth()?;
        let current_provider = SamlProvider::get(self, &provider.arn, &provider.namespace)?;
        let url_string = format!("http://example.com/?param={}", provider.metadata_docucment);
        let url = Url::parse(&url_string).expect("Failed to parse metadata docucment");
        let (_, value) = url.query_pairs().next().expect("metadata docucment");
        if value != current_provider.metadata_docucment {
            SamlProvider::update(self, &provider)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete the SAML Identity Provider.
    ///
    /// arn: The ARN of the provider to delete.
    /// namespace: ECS namespace IAM entity belongs to
    ///
    pub fn delete_saml_provider(&mut self, arn: &str, namespace: &str) -> Result<()> {
        self.auth()?;
        SamlProvider::delete(self, arn, namespace)
    }

    /// List the SAML Identity Providers.
    ///
    /// namespace: ECS namespace IAM entity belongs to
    ///
    pub fn list_saml_providers(&mut self, namespace: &str) -> Result<Vec<SamlProvider>> {
        self.auth()?;
        SamlProvider::list(self, namespace)
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
    ) -> Result<Vec<UserGroupMembership>> {
        self.auth()?;
        UserGroupMembership::list_by_group(self, group_name, namespace)
    }

    /// Add Inline Policy for IAM User.
    ///
    /// user_inline_policy: UserInlinePolicy to create
    ///
    pub fn create_user_inline_policy(
        &mut self,
        user_inline_policy: UserInlinePolicy,
    ) -> Result<UserInlinePolicy> {
        self.auth()?;
        UserInlinePolicy::create(self, &user_inline_policy)?;
        UserInlinePolicy::get(
            self,
            &user_inline_policy.user_name,
            &user_inline_policy.policy_name,
            &user_inline_policy.namespace,
        )
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
    ) -> Result<UserInlinePolicy> {
        self.auth()?;
        UserInlinePolicy::get(self, user_name, policy_name, namespace)
    }

    /// Update Inline Policy for IAM User.
    ///
    /// user_inline_policy: UserInlinePolicy to update
    ///
    pub fn update_user_inline_policy(
        &mut self,
        user_inline_policy: UserInlinePolicy,
    ) -> Result<bool> {
        self.auth()?;
        UserInlinePolicy::update(self, &user_inline_policy)
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
    ) -> Result<()> {
        self.auth()?;
        UserInlinePolicy::delete(self, user_name, policy_name, namespace)
    }

    /// Lists all user inline policies.
    ///
    pub fn list_user_inline_policies(
        &mut self,
        user_name: &str,
        namespace: &str,
    ) -> Result<Vec<UserInlinePolicy>> {
        self.auth()?;
        UserInlinePolicy::list(self, user_name, namespace)
    }

    /// Add Inline Policy for IAM Group.
    ///
    /// group_inline_policy: GroupInlinePolicy to create
    ///
    pub fn create_group_inline_policy(
        &mut self,
        group_inline_policy: GroupInlinePolicy,
    ) -> Result<GroupInlinePolicy> {
        self.auth()?;
        GroupInlinePolicy::create(self, &group_inline_policy)?;
        GroupInlinePolicy::get(
            self,
            &group_inline_policy.group_name,
            &group_inline_policy.policy_name,
            &group_inline_policy.namespace,
        )
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
    ) -> Result<GroupInlinePolicy> {
        self.auth()?;
        GroupInlinePolicy::get(self, group_name, policy_name, namespace)
    }

    /// Update Inline Policy for IAM group.
    ///
    /// group_inline_policy: GroupInlinePolicy to update
    ///
    pub fn update_group_inline_policy(
        &mut self,
        group_inline_policy: GroupInlinePolicy,
    ) -> Result<bool> {
        self.auth()?;
        GroupInlinePolicy::update(self, &group_inline_policy)
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
    ) -> Result<()> {
        self.auth()?;
        GroupInlinePolicy::delete(self, group_name, policy_name, namespace)
    }

    /// Lists all group inline policies.
    ///
    pub fn list_group_inline_policies(
        &mut self,
        group_name: &str,
        namespace: &str,
    ) -> Result<Vec<GroupInlinePolicy>> {
        self.auth()?;
        GroupInlinePolicy::list(self, group_name, namespace)
    }

    /// Gets the list of buckets for the specified namespace.
    ///
    /// namespace: Namespace for which buckets should be listed. Cannot be empty.
    /// name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
    ///
    pub fn list_buckets(&mut self, namespace: &str, name_prefix: &str) -> Result<Vec<Bucket>> {
        self.auth()?;
        Bucket::list(self, namespace, name_prefix)
    }

    /// Create an bucket.
    ///
    /// bucket: Bucket to create.
    ///
    pub fn create_bucket(&mut self, bucket: Bucket) -> Result<Bucket> {
        self.auth()?;
        Bucket::create(self, &bucket)?;
        Bucket::update(self, &bucket)?;
        Bucket::get(self, &bucket.name, &bucket.namespace)
    }

    /// Gets bucket information for the specified bucket.
    ///
    /// name: Bucket name for which information will be retrieved. Cannot be empty.
    /// namespace: Namespace associated. Cannot be empty.
    ///
    pub fn get_bucket(&mut self, name: &str, namespace: &str) -> Result<Bucket> {
        self.auth()?;
        Bucket::get(self, name, namespace)
    }

    /// Update an bucket.
    ///
    /// bucket: Bucket to update.
    ///
    pub fn update_bucket(&mut self, bucket: Bucket) -> Result<bool> {
        self.auth()?;
        Bucket::update(self, &bucket)
    }

    /// Deletes the specified bucket.
    ///
    /// name: Bucket name to be deleted. Cannot be empty.
    /// namespace: Namespace associated. Cannot be empty.
    /// emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
    ///
    pub fn delete_bucket(&mut self, name: &str, namespace: &str, empty_bucket: bool) -> Result<()> {
        self.auth()?;
        Bucket::delete(self, name, namespace, empty_bucket)
    }

    /// Creates a namespace with the given details.
    ///
    /// namespace: Namespace to create
    ///
    pub fn create_namespace(&mut self, namespace: Namespace) -> Result<Namespace> {
        self.auth()?;
        let new_namespace = Namespace::create(self, &namespace)?;
        let id = new_namespace.id.clone();
        // update retention class
        Namespace::update(self, namespace, Some(new_namespace))?;
        Namespace::get(self, &id)
    }

    /// Gets the details for the given namespace.
    ///
    /// id: Namespace identifier for which details needs to be retrieved.
    ///
    pub fn get_namespace(&mut self, id: &str) -> Result<Namespace> {
        self.auth()?;
        Namespace::get(self, id)
    }

    /// Update a namespace with the given details.
    ///
    /// namespace: Namespace to be updated
    ///
    pub fn update_namespace(&mut self, namespace: Namespace) -> Result<bool> {
        self.auth()?;
        Namespace::update(self, namespace, None)
    }

    /// Deactivates and deletes the given namespace and all associated user mappings.
    ///
    /// id: An active namespace identifier which needs to be deactivated/deleted
    ///
    pub fn delete_namespace(&mut self, id: &str) -> Result<()> {
        self.auth()?;
        Namespace::delete(self, id)
    }

    /// Gets the list of all configured namespaces.
    ///
    /// name_prefix: Case sensitive prefix of the Namespace name with a wild card(*) Ex : any_prefix_string*.
    ///
    pub fn list_namespaces(&mut self, name_prefix: &str) -> Result<Vec<Namespace>> {
        self.auth()?;
        Namespace::list(self, name_prefix)
    }

    /// Creates local users for the VDC.
    ///
    /// user: ManagementUser to create
    ///
    pub fn create_management_user(&mut self, user: ManagementUser) -> Result<ManagementUser> {
        self.auth()?;
        ManagementUser::create(self, &user)
    }

    /// Gets details for the specified local management user.
    ///
    /// id: User identifier for which local user information needs to be retrieved
    ///
    pub fn get_management_user(&mut self, id: &str) -> Result<ManagementUser> {
        self.auth()?;
        ManagementUser::get(self, id)
    }

    /// Updates user details for the specified local management user.
    ///
    /// user: ManagementUser to be updated
    ///
    pub fn update_management_user(&mut self, user: ManagementUser) -> Result<bool> {
        self.auth()?;
        ManagementUser::update(self, user)
    }

    /// Deletes local management user information for the specified user identifier.
    ///
    /// id: User identifier for which local user information needs to be deleted.
    ///
    pub fn delete_management_user(&mut self, id: &str) -> Result<()> {
        self.auth()?;
        ManagementUser::delete(self, id)
    }

    /// Gets all configured local management users.
    ///
    pub fn list_management_users(&mut self) -> Result<Vec<ManagementUser>> {
        self.auth()?;
        ManagementUser::list(self)
    }

    /// Creates a user for a specified namespace.
    ///
    /// user: ObjectUser to create
    ///
    pub fn create_object_user(&mut self, user: ObjectUser) -> Result<ObjectUser> {
        self.auth()?;
        ObjectUser::create(self, &user)?;
        ObjectUser::update(self, &user)?;
        ObjectUser::get(self, &user.name, &user.namespace)
    }

    /// Gets user details for the specified user belong to the specified namespace.
    ///
    /// name: Valid user identifier
    /// namespace: The namespace to which user belong
    ///
    pub fn get_object_user(&mut self, name: &str, namespace: &str) -> Result<ObjectUser> {
        self.auth()?;
        ObjectUser::get(self, name, namespace)
    }

    /// Updates user details for the specified object user.
    ///
    /// user: ObjectUser to be updated
    ///
    pub fn update_object_user(&mut self, user: ObjectUser) -> Result<bool> {
        self.auth()?;
        ObjectUser::update(self, &user)
    }

    /// Deletes the specified user and its secret keys.
    ///
    /// name: User to be deleted.
    /// namespace: Namespace identifier to associate with the user
    ///
    pub fn delete_object_user(&mut self, name: &str, namespace: &str) -> Result<()> {
        self.auth()?;
        ObjectUser::delete(self, name, namespace)
    }

    /// Gets identifiers for all configured users.
    ///
    pub fn list_object_users(&mut self) -> Result<Vec<ObjectUser>> {
        self.auth()?;
        ObjectUser::list(self)
    }

    /// Get the certificate chain being used by ECS
    ///
    pub fn get_vdc_keystore(&mut self) -> Result<VdcKeystore> {
        self.auth()?;
        VdcKeystore::get(self)
    }

    /// Set the certificate chain being used by ECS.
    ///
    /// keystore: VdcKeystore to be updated
    ///
    pub fn update_vdc_keystore(&mut self, keystore: VdcKeystore) -> Result<bool> {
        self.auth()?;
        let current_keystore = VdcKeystore::get(self)?;
        if keystore.chain != current_keystore.chain
            || keystore.private_key != current_keystore.private_key
        {
            VdcKeystore::update(self, &keystore)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Create a VDC with the specified details.
    ///
    /// vdc: VDC to be created
    ///
    pub fn create_vdc(&mut self, vdc: Vdc) -> Result<Vdc> {
        self.auth()?;
        Vdc::create(self, &vdc)?;
        Vdc::get(self, &vdc.vdc_name)
    }

    /// Gets the details for a VDC the identify of which is specified by its name.
    ///
    /// name: VDC name for which VDC Information is to be retrieved
    ///
    pub fn get_vdc(&mut self, name: &str) -> Result<Vdc> {
        self.auth()?;
        Vdc::get(self, name)
    }

    /// Update VDC info
    ///
    /// vdc: VDC to be updated
    ///
    pub fn update_vdc(&mut self, vdc: Vdc) -> Result<bool> {
        self.auth()?;
        Vdc::update(self, &vdc)
    }

    /// Deactivates and deletes a VDC.
    ///
    /// id: VDC identifier for which VDC Information needs to be deleted
    ///
    pub fn delete_vdc(&mut self, id: &str) -> Result<()> {
        self.auth()?;
        Vdc::delete(self, id)
    }

    /// Gets all details of all configured VDCs.
    ///
    pub fn list_vdcs(&mut self) -> Result<Vec<Vdc>> {
        self.auth()?;
        Vdc::list(self)
    }

    /// Create a storage pool with the specified details.
    ///
    /// sp: Storage pool to be created
    ///
    pub fn create_storage_pool(&mut self, sp: StoragePool) -> Result<StoragePool> {
        self.auth()?;
        StoragePool::create(self, &sp)
    }

    /// Gets the details for the specified storage pool.
    ///
    /// id: Storage pool identifier to be retrieved
    ///
    pub fn get_storage_pool(&mut self, id: &str) -> Result<StoragePool> {
        self.auth()?;
        StoragePool::get(self, id)
    }

    /// Updates storage pool for the specified identifier..
    ///
    /// sp: Storage pool to be updated
    ///
    pub fn update_storage_pool(&mut self, sp: StoragePool) -> Result<bool> {
        self.auth()?;
        StoragePool::update(self, &sp)
    }

    /// Gets a list of storage pools from the local VDC.
    ///
    pub fn list_storage_pools(&mut self) -> Result<Vec<StoragePool>> {
        self.auth()?;
        StoragePool::list(self)
    }

    /// Creates a replication group that includes the specified storage pools
    ///
    /// rg: ReplicationGroup to create
    ///
    pub fn create_replication_group(&mut self, rg: ReplicationGroup) -> Result<ReplicationGroup> {
        self.auth()?;
        ReplicationGroup::create(self, &rg)?;
        let list = ReplicationGroup::list(self)?;
        list.into_iter()
            .find(|item| rg.name == item.name)
            .ok_or_else(|| anyhow!("Replication group with name {} not found", rg.name))
    }

    /// Gets the details for the specified replication group.
    ///
    /// id: Replication group identifier for which details needs to be retrieved
    ///
    pub fn get_replication_group(&mut self, id: &str) -> Result<ReplicationGroup> {
        self.auth()?;
        // ReplicationGroup::get won't return the latest value after update
        // so use list instead
        let list = ReplicationGroup::list(self)?;
        list.into_iter()
            .find(|rg| rg.id == id)
            .ok_or_else(|| anyhow!("Replication group with id {} not found", id))
    }

    /// Updates the name and description for a replication group.
    ///
    /// rg: Replication group which details needs to be updated
    ///
    pub fn update_replication_group(&mut self, rg: ReplicationGroup) -> Result<bool> {
        self.auth()?;
        ReplicationGroup::update(self, &rg)
    }

    /// Lists all configured replication groups.
    ///
    pub fn list_replication_groups(&mut self) -> Result<Vec<ReplicationGroup>> {
        self.auth()?;
        ReplicationGroup::list(self)
    }
}
