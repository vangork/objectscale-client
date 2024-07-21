#![allow(unused_imports)]

use crate::bucket::{Bucket, BucketTag, Link, MetaData, MinMaxGovernor, SearchMetaData};
use crate::iam::{
    AccessKey, Account, AccountAccessKey, EntitiesForPolicy, Group, GroupPolicyAttachment,
    LoginProfile, PermissionsBoundary, Policy, Role, RolePolicyAttachment, Tag, User,
    UserGroupMembership, UserPolicyAttachment,
};
use crate::tenant::Tenant;
use objectscale_client::{bucket, client, iam, tenant};
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

    pub fn new_objectstore_client(&self, endpoint: &str) -> PyResult<ObjectstoreClient> {
        let result = self.management_client.new_objectstore_client(endpoint);
        match result {
            Ok(objectstore_client) => Ok(ObjectstoreClient { objectstore_client }),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Create an IAM account.
    ///
    /// account: Iam Account to create
    ///
    pub fn create_account(&mut self, account: &Account) -> PyResult<Account> {
        let account = iam::Account::from(account.clone());
        let result = self.management_client.create_account(account);
        match result {
            Ok(account) => Ok(Account::from(account)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Get an IAM account.
    ///
    /// account_id: Id of the account
    ///
    pub fn get_account(&mut self, account_id: &str) -> PyResult<Account> {
        let result = self.management_client.get_account(account_id);
        match result {
            Ok(account) => Ok(Account::from(account)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update an IAM account.
    ///
    /// account: Iam Account to update
    ///
    pub fn update_account(&mut self, account: &Account) -> PyResult<Account> {
        let account = iam::Account::from(account.clone());
        let result = self.management_client.update_account(account);
        match result {
            Ok(account) => Ok(Account::from(account)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete an IAM account.
    ///
    /// account_id: Id of the account
    ///
    pub fn delete_account(&mut self, account_id: &str) -> PyResult<()> {
        let result = self.management_client.delete_account(account_id);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// List all IAM accounts.
    ///
    pub fn list_accounts(&mut self) -> PyResult<Vec<Account>> {
        let result = self.management_client.list_accounts();
        match result {
            Ok(accounts) => Ok(accounts.into_iter().map(Account::from).collect()),
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

    /// Returns the information about the specified IAM User.
    ///
    /// user_name: The name of the user to retrieve. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn get_user(&mut self, user_name: &str, namespace: &str) -> PyResult<User> {
        let result = self.management_client.get_user(user_name, namespace);
        match result {
            Ok(user) => Ok(User::from(user)),
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
    /// TODO:
    /// list_user won't show tags, or permissions boundary if any
    /// fix it or report bug
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

    /// Creates a password for the specified IAM user.
    ///
    /// login_profile: LoginProfile to create
    ///
    pub fn create_login_profile(&mut self, login_profile: &LoginProfile) -> PyResult<LoginProfile> {
        let login_profile = iam::LoginProfile::from(login_profile.clone());
        let result = self.management_client.create_login_profile(login_profile);
        match result {
            Ok(login_profile) => Ok(LoginProfile::from(login_profile)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Retrieves the password for the specified IAM user
    ///
    /// user_name: Name of the user to delete password. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn get_login_profile(
        &mut self,
        user_name: &str,
        namespace: &str,
    ) -> PyResult<LoginProfile> {
        let result = self
            .management_client
            .get_login_profile(user_name, namespace);
        match result {
            Ok(login_profile) => Ok(LoginProfile::from(login_profile)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Deletes the password for the specified IAM user
    ///
    /// user_name: Name of the user to delete password. Cannot be empty.
    /// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
    ///
    pub fn delete_login_profile(&mut self, user_name: &str, namespace: &str) -> PyResult<()> {
        let result = self
            .management_client
            .delete_login_profile(user_name, namespace);
        match result {
            Ok(_) => Ok(()),
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
    pub fn update_access_key(&mut self, access_key: &AccessKey) -> PyResult<AccessKey> {
        let access_key = iam::AccessKey::from(access_key.clone());
        let result = self.management_client.update_access_key(access_key);
        match result {
            Ok(access_key) => Ok(AccessKey::from(access_key)),
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

    /// Creates account AccessKey.
    ///
    /// account_access_key: Account Access Key to create
    ///
    pub fn create_account_access_key(
        &mut self,
        account_access_key: &AccountAccessKey,
    ) -> PyResult<AccountAccessKey> {
        let account_access_key = iam::AccountAccessKey::from(account_access_key.clone());
        let result = self
            .management_client
            .create_account_access_key(account_access_key);
        match result {
            Ok(account_access_key) => Ok(AccountAccessKey::from(account_access_key)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates account AccessKey.
    ///
    /// account_access_key: Account Access Key to update
    ///
    pub fn update_account_access_key(
        &mut self,
        account_access_key: &AccountAccessKey,
    ) -> PyResult<AccountAccessKey> {
        let account_access_key = iam::AccountAccessKey::from(account_access_key.clone());
        let result = self
            .management_client
            .update_account_access_key(account_access_key);
        match result {
            Ok(account_access_key) => Ok(AccountAccessKey::from(account_access_key)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
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
    ) -> PyResult<()> {
        let result = self
            .management_client
            .delete_account_access_key(access_key_id, account_id);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Returns information about the access key IDs associated with the specified IAM account.
    ///
    /// account_id: The id of the account. Cannot be empty.
    ///
    pub fn list_account_access_keys(
        &mut self,
        account_id: &str,
    ) -> PyResult<Vec<AccountAccessKey>> {
        let result = self.management_client.list_account_access_keys(account_id);
        match result {
            Ok(account_access_keys) => Ok(account_access_keys
                .into_iter()
                .map(AccountAccessKey::from)
                .collect()),
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
    pub fn update_role(&mut self, role: &Role) -> PyResult<Role> {
        let role = iam::Role::from(role.clone());
        let result = self.management_client.update_role(role);
        match result {
            Ok(role) => Ok(Role::from(role)),
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
}

// ObjectstoreClient manages ObjectScale resources on ObjectStore with the ObjectScale ObjectStore REST APIs.
#[pyclass]
pub(crate) struct ObjectstoreClient {
    objectstore_client: client::ObjectstoreClient,
}

#[pymethods]
impl ObjectstoreClient {
    /// Create an bucket.
    ///
    /// bucket: Bucket to create.
    ///
    pub fn create_bucket(&mut self, bucket: &Bucket) -> PyResult<Bucket> {
        let bucket = bucket::Bucket::from(bucket.clone());
        let result = self.objectstore_client.create_bucket(bucket);
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
        let result = self.objectstore_client.get_bucket(name, namespace);
        match result {
            Ok(bucket) => Ok(Bucket::from(bucket)),
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
            .objectstore_client
            .delete_bucket(name, namespace, empty_bucket);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Update an bucket.
    ///
    /// bucket: Bucket to update.
    ///
    pub fn update_bucket(&mut self, bucket: &Bucket) -> PyResult<Bucket> {
        let bucket = bucket::Bucket::from(bucket.clone());
        let result = self.objectstore_client.update_bucket(bucket);
        match result {
            Ok(bucket) => Ok(Bucket::from(bucket)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Gets the list of buckets for the specified namespace.
    ///
    /// namespace: Namespace for which buckets should be listed. Cannot be empty.
    /// name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
    ///
    pub fn list_buckets(&mut self, namespace: &str, name_prefix: &str) -> PyResult<Vec<Bucket>> {
        let result = self.objectstore_client.list_buckets(namespace, name_prefix);
        match result {
            Ok(buckets) => Ok(buckets.into_iter().map(Bucket::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Creates the tenant which will associate an IAM Account within an objectstore.
    ///
    /// tenant: Tenant to create
    ///
    pub fn create_tenant(&mut self, tenant: &Tenant) -> PyResult<Tenant> {
        let tenant = tenant::Tenant::from(tenant.clone());
        let result = self.objectstore_client.create_tenant(tenant);
        match result {
            Ok(tenant) => Ok(Tenant::from(tenant)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Get the tenant.
    ///
    /// name: The associated account id. Cannot be empty.
    ///
    pub fn get_tenant(&mut self, name: &str) -> PyResult<Tenant> {
        let result = self.objectstore_client.get_tenant(name);
        match result {
            Ok(tenant) => Ok(Tenant::from(tenant)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Updates Tenant details like default_bucket_size and alias.
    ///
    /// tenant: Tenant to update
    ///
    pub fn update_tenant(&mut self, tenant: &Tenant) -> PyResult<Tenant> {
        let tenant = tenant::Tenant::from(tenant.clone());
        let result = self.objectstore_client.update_tenant(tenant);
        match result {
            Ok(tenant) => Ok(Tenant::from(tenant)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Delete the tenant from an object store. Tenant must not own any buckets.
    ///
    /// name: The associated account id. Cannot be empty.
    ///
    pub fn delete_tenant(&mut self, name: &str) -> PyResult<()> {
        let result = self.objectstore_client.delete_tenant(name);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    /// Get the list of tenants.
    ///
    /// name_prefix: Case sensitive prefix of the tenant name with a wild card(*). Can be empty or any_prefix_string*.
    ///
    pub fn list_tenants(&mut self, name_prefix: &str) -> PyResult<Vec<Tenant>> {
        let result = self.objectstore_client.list_tenants(name_prefix);
        match result {
            Ok(tenants) => Ok(tenants.into_iter().map(Tenant::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }
}
