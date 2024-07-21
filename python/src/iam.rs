use objectscale_client::iam;
use pyo3::prelude::*;
use std::convert::From;

// IAM User access key
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct AccessKey {
    // The Id of this access key
    access_key_id: String,
    // The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
    create_date: String,
    // The secret key
    secret_access_key: String,
    // The status of the access key {Active | Inactive}
    status: String,
    // The name of the user that the access key is associated with.
    #[pyo3(set)]
    user_name: String,
    //
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
        format!("{:?}", self)
    }
}

// An ObjectScale Account is a logical construct that corresponds to a customer business unit, tenant, project, and so on.
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct Account {
    // The Id of the account
    account_id: String,
    // The name/id of the object scale that the account is associated with
    objscale: String,
    // The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the account created
    create_date: String,
    // Indicate if encryption is enabled for the account
    #[pyo3(set)]
    encryption_enabled: bool,
    // account disabled
    account_disabled: bool,
    // An Alias for an account
    #[pyo3(set)]
    alias: String,
    // The description for an account
    #[pyo3(set)]
    description: String,
    // protection enabled
    protection_enabled: bool,
    // Tso id
    tso_id: String,
    // Labels
    #[pyo3(set)]
    tags: Vec<Tag>,
}

impl From<iam::Account> for Account {
    fn from(account: iam::Account) -> Self {
        Self {
            account_id: account.account_id,
            objscale: account.objscale,
            create_date: account.create_date,
            encryption_enabled: account.encryption_enabled,
            account_disabled: account.account_disabled,
            alias: account.alias,
            description: account.description,
            protection_enabled: account.protection_enabled,
            tso_id: account.tso_id,
            tags: account.tags.into_iter().map(Tag::from).collect(),
        }
    }
}

impl From<Account> for iam::Account {
    fn from(account: Account) -> Self {
        Self {
            account_id: account.account_id,
            objscale: account.objscale,
            create_date: account.create_date,
            encryption_enabled: account.encryption_enabled,
            account_disabled: account.account_disabled,
            alias: account.alias,
            description: account.description,
            protection_enabled: account.protection_enabled,
            tso_id: account.tso_id,
            tags: account.tags.into_iter().map(iam::Tag::from).collect(),
        }
    }
}

#[pymethods]
impl Account {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{:?}", self)
    }
}

// IAM Account access key
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct AccountAccessKey {
    // The Id of this access key
    access_key_id: String,
    // The date and time, in the format of YYYY-MM-DDTHH:mm:ssZ, when the access key was created.
    create_date: String,
    // The secret key
    secret_access_key: String,
    // The status of the access key {Active | Inactive}
    status: String,
    // The name of the user that the access key is associated with.
    #[pyo3(set)]
    account_id: String,
}

impl From<iam::AccountAccessKey> for AccountAccessKey {
    fn from(account_access_key: iam::AccountAccessKey) -> Self {
        Self {
            access_key_id: account_access_key.access_key_id,
            create_date: account_access_key.create_date,
            secret_access_key: account_access_key.secret_access_key,
            status: account_access_key.status,
            account_id: account_access_key.account_id,
        }
    }
}

impl From<AccountAccessKey> for iam::AccountAccessKey {
    fn from(account_access_key: AccountAccessKey) -> Self {
        Self {
            access_key_id: account_access_key.access_key_id,
            create_date: account_access_key.create_date,
            secret_access_key: account_access_key.secret_access_key,
            status: account_access_key.status,
            account_id: account_access_key.account_id,
        }
    }
}

#[pymethods]
impl AccountAccessKey {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{:?}", self)
    }
}

//
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct EntitiesForPolicy {
    //
    #[pyo3(set)]
    users: Vec<String>,
    //
    #[pyo3(set)]
    groups: Vec<String>,
    //
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
        format!("{:?}", self)
    }
}

// A Group is a collection of Users. You can use groups to specify permissions for a collection of users.
#[derive(Clone, Debug, Default)]
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
    // Simple name identifying the Group.
    #[pyo3(set)]
    group_name: String,
    //
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
        format!("{:?}", self)
    }
}

//
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct GroupPolicyAttachment {
    //
    #[pyo3(set)]
    group_name: String,
    //
    policy_name: String,
    //
    #[pyo3(set)]
    policy_arn: String,
    //
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
        format!("{:?}", self)
    }
}

//
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct LoginProfile {
    //
    create_date: String,
    //
    #[pyo3(set)]
    user_name: String,
    //
    #[pyo3(set)]
    password_reset_required: bool,
    //
    #[pyo3(set)]
    password: String,
    //
    #[pyo3(set)]
    namespace: String,
}

impl From<iam::LoginProfile> for LoginProfile {
    fn from(login_profile: iam::LoginProfile) -> Self {
        Self {
            create_date: login_profile.create_date,
            user_name: login_profile.user_name,
            password_reset_required: login_profile.password_reset_required,
            password: login_profile.password,
            namespace: login_profile.namespace,
        }
    }
}

impl From<LoginProfile> for iam::LoginProfile {
    fn from(login_profile: LoginProfile) -> Self {
        Self {
            create_date: login_profile.create_date,
            user_name: login_profile.user_name,
            password_reset_required: login_profile.password_reset_required,
            password: login_profile.password,
            namespace: login_profile.namespace,
        }
    }
}

#[pymethods]
impl LoginProfile {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{:?}", self)
    }
}

//
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct PermissionsBoundary {
    // The ARN of the policy set as permissions boundary.
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
        format!("{:?}", self)
    }
}

// IAM policies are documents in JSON format that define permissions for an operation regardless of the method that you use to perform the operation.
#[derive(Clone, Debug, Default)]
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
    // A friendly description of the policy.
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
    // The friendly name of the policy.
    #[pyo3(set)]
    policy_name: String,
    // The date and time, in ISO 8601 date-time format, when the policy was created.
    update_date: String,
    //
    #[pyo3(set)]
    policy_document: String,
    //
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
        format!("{:?}", self)
    }
}

// A role is similar to a user, in that it is an identity with permission policies that determine what the identity can and cannot do.
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct Role {
    // Arn that identifies the role.
    arn: String,
    // The trust relationship policy document that grants an entity permission to assume the role.
    #[pyo3(set)]
    assume_role_policy_document: String,
    // ISO 8601 DateTime when role was created.
    create_date: String,
    // The description of the IAM role.
    #[pyo3(set)]
    description: String,
    // The maximum session duration (in seconds) that you want to set for the specified role.
    #[pyo3(set)]
    max_session_duration: i32,
    // The path to the IAM role.
    path: String,
    // Unique Id associated with the role.
    role_id: String,
    // Simple name identifying the role.
    #[pyo3(set)]
    role_name: String,
    // The list of Tags associated with the role.
    #[pyo3(set)]
    tags: Vec<Tag>,
    // Permissions boundary
    #[pyo3(set)]
    permissions_boundary: PermissionsBoundary,
    //
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
            tags: role.tags.into_iter().map(Tag::from).collect(),
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
            tags: role.tags.into_iter().map(iam::Tag::from).collect(),
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
        format!("{:?}", self)
    }
}

//
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct RolePolicyAttachment {
    //
    #[pyo3(set)]
    role_name: String,
    //
    policy_name: String,
    //
    #[pyo3(set)]
    policy_arn: String,
    //
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
        format!("{:?}", self)
    }
}

// Lables for IAM account, role and user.
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct Tag {
    // tag key
    #[pyo3(set)]
    key: String,
    // tag value
    #[pyo3(set)]
    value: String,
}

impl From<iam::Tag> for Tag {
    fn from(tag: iam::Tag) -> Self {
        Self {
            key: tag.key,
            value: tag.value,
        }
    }
}

impl From<Tag> for iam::Tag {
    fn from(tag: Tag) -> Self {
        Self {
            key: tag.key,
            value: tag.value,
        }
    }
}

#[pymethods]
impl Tag {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{:?}", self)
    }
}

// In ObjectScale, an IAM User is a person or application in the account.
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct User {
    // Arn that identifies the user.
    arn: String,
    // ISO 8601 format DateTime when user was created.
    create_date: String,
    // The path to the IAM User.
    path: String,
    // Permissions boundary
    #[pyo3(set)]
    permissions_boundary: PermissionsBoundary,
    // Unique Id associated with the User.
    user_id: String,
    // Simple name identifying the User.
    #[pyo3(set)]
    user_name: String,
    // The list of Tags associated with the User.
    #[pyo3(set)]
    tags: Vec<Tag>,
    //
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
            tags: user.tags.into_iter().map(Tag::from).collect(),
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
            tags: user.tags.into_iter().map(iam::Tag::from).collect(),
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
        format!("{:?}", self)
    }
}

//
#[derive(Clone, Debug, Default)]
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
        format!("{:?}", self)
    }
}

//
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct UserPolicyAttachment {
    //
    #[pyo3(set)]
    user_name: String,
    //
    policy_name: String,
    //
    #[pyo3(set)]
    policy_arn: String,
    //
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
        format!("{:?}", self)
    }
}
