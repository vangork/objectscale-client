//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

//! Applications should always use this ManagementClient to manage ObjectScale resources.
//!

use crate::bucket::Bucket;
use crate::iam::{
    AccessKey, Account, AccountAccessKey, EntitiesForPolicy, Group, GroupPolicyAttachment,
    LoginProfile, Policy, Role, RolePolicyAttachment, User, UserGroupMembership,
    UserPolicyAttachment,
};
use crate::response::get_content_text;
use crate::tenant::Tenant;
use anyhow::{anyhow, Context as _, Result};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ManagementClient manages ObjectScale resources with the ObjectScale management REST APIs.
///
/// # Examples
/// ```no_run
/// use objectscale_client::client::ManagementClient;
/// use objectscale_client::iam::AccountBuilder;
///
/// fn main() {
///     let endpoint = "https://192.168.1.1:443";
///     let username = "admin";
///     let password = "pass";
///     let insecure = false;
///     let account_alias = "test";
///     let mut client = ManagementClient::new(endpoint, username, password, insecure).expect("management client");
///     let account = AccountBuilder::default().alias(account_alias).build().expect("build account");
///     let account = client.create_account(account).expect("create account");
///     println!("Created account: {:?}", account);
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
    refresh_token: Option<String>,
    refresh_expires_in: Option<u64>,
}

/// ObjectstoreClient manages ObjectScale resources on ObjectStore with the ObjectScale ObjectStore REST APIs.
///
/// # Examples
/// ```no_run
/// use objectscale_client::client::ManagementClient;
/// use objectscale_client::iam::AccountBuilder;
/// use objectscale_client::tenant::TenantBuilder;
///
/// fn main() {
///     let endpoint = "https://192.168.1.1:443";
///     let username = "admin";
///     let password = "pass";
///     let insecure = false;
///     let objectstore_endpoint = "https://192.168.1.2:4443";
///     let account_alias = "test";
///     let mut management_client = ManagementClient::new(endpoint, username, password, insecure).expect("management client");
///     let mut objectstore_client = management_client.new_objectstore_client(objectstore_endpoint).expect("objectstore client");
///     let account = AccountBuilder::default().alias(account_alias).build().expect("build account");
///     let account = management_client.create_account(account).expect("create account");
///     let tenant_alias = "test";
///     let tenant = TenantBuilder::default().alias(tenant_alias).id(&account.account_id).build().expect("build tenant");
///     let tenant = objectstore_client.create_tenant(tenant).expect("create tenant");
///     println!("Created tenant: {:?}", tenant);
/// }
/// ```
pub struct ObjectstoreClient {
    pub(crate) endpoint: Url,
    pub(crate) management_client: ManagementClient,
}

#[derive(Debug, Serialize)]
struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
struct AuthLoginResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct RefreshTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
    pub token_type: String,
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
            refresh_token: None,
            refresh_expires_in: None,
        })
    }

    pub fn new_objectstore_client(&self, endpoint: &str) -> Result<ObjectstoreClient> {
        Ok(ObjectstoreClient {
            endpoint: Url::parse(endpoint)?,
            management_client: self.clone(),
        })
    }

    fn obtain_auth_token(&mut self) -> Result<()> {
        let params = BasicAuth {
            username: self.username.clone(),
            password: self.password.clone(),
        };
        let request_url = format!("{}mgmt/auth/login", self.endpoint);
        let resp = self
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&params)
            .send()?;

        let text = get_content_text(resp)?;
        let resp: AuthLoginResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise AuthLoginResponse. Body was: \"{}\"",
                text
            )
        })?;
        let obtain_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        self.access_token = Some(resp.access_token);
        self.refresh_token = Some(resp.refresh_token);
        self.expires_in = Some(resp.expires_in + obtain_time);
        self.refresh_expires_in = Some(resp.refresh_expires_in + obtain_time);
        Ok(())
    }

    fn refresh_auth_token(&mut self) -> Result<()> {
        let request_url = format!(
            "{}mgmt/auth/token?grant_type=refresh_token&refresh_token={}",
            self.endpoint,
            self.refresh_token.clone().unwrap()
        );
        let resp = self
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .send()?;

        let text = get_content_text(resp)?;
        let resp: RefreshTokenResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise RefreshTokenResponse. Body was: \"{}\"",
                text
            )
        })?;
        self.access_token = Some(resp.access_token);
        self.refresh_token = Some(resp.refresh_token);
        self.expires_in = Some(resp.expires_in);
        self.refresh_expires_in = Some(resp.refresh_expires_in);
        Ok(())
    }

    fn auth(&mut self) -> Result<()> {
        if self.access_token.is_none() {
            self.obtain_auth_token()?;
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if self.expires_in.unwrap() > now {
            } else if self.refresh_expires_in.unwrap() > now {
                self.refresh_auth_token()?;
            } else {
                self.obtain_auth_token()?;
            }
        }
        Ok(())
    }

    /// Create an IAM account.
    ///
    /// account: Iam Account to create
    ///
    pub fn create_account(&mut self, account: Account) -> Result<Account> {
        self.auth()?;
        if account.tags.is_empty() {
            Account::create_account(self, account)
        } else {
            let tags = account.tags.clone();
            let account = Account::create_account(self, account)?;
            Account::tag_account(self, account.account_id.as_str(), tags)?;
            Account::get_account(self, account.account_id.as_str())
        }
    }

    /// Get an IAM account.
    ///
    /// account_id: Id of the account
    ///
    pub fn get_account(&mut self, account_id: &str) -> Result<Account> {
        self.auth()?;
        Account::get_account(self, account_id)
    }

    /// Update an IAM account.
    ///
    /// account: Iam Account to update
    ///
    pub fn update_account(&mut self, account: Account) -> Result<Account> {
        self.auth()?;
        Account::update_account(self, account)
    }

    /// Delete an IAM account.
    ///
    /// account_id: Id of the account
    ///
    pub fn delete_account(&mut self, account_id: &str) -> Result<()> {
        self.auth()?;
        let account = Account::get_account(self, account_id)?;
        if !account.account_disabled {
            Account::disable_account(self, account_id)?;
        }
        Account::delete_account(self, account_id)
    }

    /// List all IAM accounts.
    ///
    pub fn list_accounts(&mut self) -> Result<Vec<Account>> {
        self.auth()?;
        Account::list_accounts(self)
    }

    /// Creates a new IAM User.
    ///
    /// user: IAM User to create
    ///
    pub fn create_user(&mut self, user: User) -> Result<User> {
        self.auth()?;
        let user = User::create(self, user)?;
        // create user request would accept tags, but the response does not contain them
        // TODO: report a bug
        User::get(self, user.user_name.as_str(), user.namespace.as_str())
    }

    /// Returns the information about the specified IAM User.
    ///
    /// user_name: The name of the user to retrieve. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn get_user(&mut self, user_name: &str, namespace: &str) -> Result<User> {
        self.auth()?;
        User::get(self, user_name, namespace)
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
    /// TODO:
    /// list_user won't show tags, or permissions boundary if any
    /// fix it or report bug
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
        UserPolicyAttachment::create(self, user_policy_attachment)
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

    /// Creates a password for the specified IAM user.
    ///
    /// login_profile: LoginProfile to create
    ///
    pub fn create_login_profile(&mut self, login_profile: LoginProfile) -> Result<LoginProfile> {
        self.auth()?;
        LoginProfile::create(self, login_profile)
    }

    /// Retrieves the password for the specified IAM user
    ///
    /// user_name: Name of the user to delete password. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn get_login_profile(&mut self, user_name: &str, namespace: &str) -> Result<LoginProfile> {
        self.auth()?;
        LoginProfile::get(self, user_name, namespace)
    }

    /// Deletes the password for the specified IAM user
    ///
    /// user_name: Name of the user to delete password. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn delete_login_profile(&mut self, user_name: &str, namespace: &str) -> Result<()> {
        self.auth()?;
        LoginProfile::delete(self, user_name, namespace)
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
    pub fn update_access_key(&mut self, access_key: AccessKey) -> Result<AccessKey> {
        self.auth()?;
        AccessKey::update(self, access_key.clone())?;
        let access_keys = self.list_access_keys(&access_key.user_name, &access_key.namespace)?;
        let access_key = access_keys
            .iter()
            .find(|key| key.access_key_id == access_key.access_key_id);
        access_key
            .map(|key| key.to_owned())
            .ok_or(anyhow!("AccessKey not found"))
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

    /// Creates account AccessKey.
    ///
    /// account_access_key: Account Access Key to create
    ///
    pub fn create_account_access_key(
        &mut self,
        account_access_key: AccountAccessKey,
    ) -> Result<AccountAccessKey> {
        self.auth()?;
        AccountAccessKey::create(self, account_access_key)
    }

    /// Updates account AccessKey.
    ///
    /// account_access_key: Account Access Key to update
    ///
    pub fn update_account_access_key(
        &mut self,
        account_access_key: AccountAccessKey,
    ) -> Result<AccountAccessKey> {
        self.auth()?;
        AccountAccessKey::update(self, account_access_key.clone())?;
        let account_access_keys = self.list_account_access_keys(&account_access_key.account_id)?;
        let account_access_key = account_access_keys
            .iter()
            .find(|key| key.access_key_id == account_access_key.access_key_id);
        account_access_key
            .map(|key| key.to_owned())
            .ok_or(anyhow!("AccountAccessKey not found"))
    }

    /// Deletes the access key pair associated with the specified IAM account.
    ///
    /// access_key_id: The ID of the access key. Cannot be empty.
    /// account_id: The id of the account. Cannot be empty.
    ///
    pub fn delete_account_access_key(
        &mut self,
        access_key_id: &str,
        account_id: &str,
    ) -> Result<()> {
        self.auth()?;
        AccountAccessKey::delete(self, access_key_id, account_id)
    }

    /// Returns information about the access key IDs associated with the specified IAM account.
    ///
    /// account_id: The id of the account. Cannot be empty.
    ///
    pub fn list_account_access_keys(&mut self, account_id: &str) -> Result<Vec<AccountAccessKey>> {
        self.auth()?;
        AccountAccessKey::list(self, account_id)
    }

    /// Create a new Managed Policy.
    ///
    /// policy: IAM Policy to create
    ///
    pub fn create_policy(&mut self, policy: Policy) -> Result<Policy> {
        self.auth()?;
        Policy::create(self, policy)
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
        GroupPolicyAttachment::create(self, group_policy_attachment)
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
    pub fn update_role(&mut self, role: Role) -> Result<Role> {
        self.auth()?;
        Role::update(self, role)
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
        RolePolicyAttachment::create(self, role_policy_attachment)
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
}

impl ObjectstoreClient {
    /// Create an bucket.
    ///
    /// bucket: Bucket to create.
    ///
    pub fn create_bucket(&mut self, bucket: Bucket) -> Result<Bucket> {
        self.management_client.auth()?;
        let namespace = bucket.namespace.clone();
        let tags = bucket.tags.clone();
        let name = Bucket::create(self, bucket)?;
        if !tags.is_empty() {
            Bucket::tag(self, &name, &namespace, tags)?;
        }
        Bucket::get(self, &name, &namespace)
    }

    /// Gets bucket information for the specified bucket.
    ///
    /// name: Bucket name for which information will be retrieved. Cannot be empty.
    /// namespace: Namespace associated. Cannot be empty.
    ///
    pub fn get_bucket(&mut self, name: &str, namespace: &str) -> Result<Bucket> {
        self.management_client.auth()?;
        Bucket::get(self, name, namespace)
    }

    /// Deletes the specified bucket.
    ///
    /// name: Bucket name to be deleted. Cannot be empty.
    /// namespace: Namespace associated. Cannot be empty.
    /// emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
    ///
    pub fn delete_bucket(&mut self, name: &str, namespace: &str, empty_bucket: bool) -> Result<()> {
        self.management_client.auth()?;
        Bucket::delete(self, name, namespace, empty_bucket)
    }

    /// Update an bucket.
    ///
    /// bucket: Bucket to update.
    ///
    pub fn update_bucket(&mut self, bucket: Bucket) -> Result<Bucket> {
        self.management_client.auth()?;
        let name = bucket.name.clone();
        let namespace = bucket.namespace.clone();
        Bucket::update(self, bucket)?;
        Bucket::get(self, &name, &namespace)
    }

    /// Gets the list of buckets for the specified namespace.
    ///
    /// namespace: Namespace for which buckets should be listed. Cannot be empty.
    /// name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
    ///
    pub fn list_buckets(&mut self, namespace: &str, name_prefix: &str) -> Result<Vec<Bucket>> {
        self.management_client.auth()?;
        Bucket::list(self, namespace, name_prefix)
    }

    /// Creates the tenant which will associate an IAM Account within an objectstore.
    ///
    /// tenant: Tenant to create
    ///
    pub fn create_tenant(&mut self, tenant: Tenant) -> Result<Tenant> {
        self.management_client.auth()?;
        Tenant::create(self, tenant)
    }

    /// Get the tenant.
    ///
    /// name: The associated account id. Cannot be empty.
    ///
    pub fn get_tenant(&mut self, name: &str) -> Result<Tenant> {
        self.management_client.auth()?;
        Tenant::get(self, name)
    }

    /// Updates Tenant details like default_bucket_size and alias.
    ///
    /// tenant: Tenant to update
    ///
    pub fn update_tenant(&mut self, tenant: Tenant) -> Result<Tenant> {
        self.management_client.auth()?;
        let tenant_id = tenant.id.clone();
        Tenant::update(self, tenant)?;
        Tenant::get(self, &tenant_id)
    }

    /// Delete the tenant from an object store. Tenant must not own any buckets.
    ///
    /// name: The associated account id. Cannot be empty.
    ///
    pub fn delete_tenant(&mut self, name: &str) -> Result<()> {
        self.management_client.auth()?;
        Tenant::delete(self, name)
    }

    /// Get the list of tenants.
    ///
    /// name_prefix: Case sensitive prefix of the tenant name with a wild card(*). Can be empty or any_prefix_string*.
    ///
    pub fn list_tenants(&mut self, name_prefix: &str) -> Result<Vec<Tenant>> {
        self.management_client.auth()?;
        Tenant::list(self, name_prefix)
    }
}
