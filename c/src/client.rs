use crate::error::{clear_error, set_error};
use crate::ffi::RCString;
use anyhow::anyhow;
use objectscale_client::client;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

/// ManagementClient manages ObjectScale resources with the ObjectScale management REST APIs.
pub struct ManagementClient {
    management_client: client::ManagementClient,
}

/// Build a new ManagementClient.
///
#[no_mangle]
pub unsafe extern "C" fn new_management_client(
    endpoint: RCString,
    username: RCString,
    password: RCString,
    insecure: bool,
    err: Option<&mut RCString>,
) -> *mut ManagementClient {
    match catch_unwind(|| {
        let endpoint = endpoint.to_string();
        let username = username.to_string();
        let password = password.to_string();

        client::ManagementClient::new(&endpoint, &username, &password, insecure)
    }) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(management_client) => {
                    let management_client = ManagementClient { management_client };
                    Box::into_raw(Box::new(management_client))
                }
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    ptr::null_mut()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during management client creation", err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn destroy_management_client(management_client: *mut ManagementClient) {
    if !management_client.is_null() {
        unsafe {
            drop(Box::from_raw(management_client));
        }
    }
}

/// Creates a new IAM User.
///
/// user: IAM User to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_user(
    management_client: *mut ManagementClient,
    user: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user = user.to_string();
        let user: objectscale_client::iam::User =
            serde_json::from_str(&user).expect("deserialize user");

        management_client.management_client.create_user(user)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|user| serde_yaml::to_string(&user).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(user) => RCString::from_str(user.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create user", err);
            RCString::null()
        }
    }
}

/// Retrieve IAM user.
///
/// name: The name of the user to retrieve.
/// namespace: ECS namespace IAM entity belongs to
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_user(
    management_client: *mut ManagementClient,
    name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .get_user(&name, &namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|user| serde_yaml::to_string(&user).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(user) => RCString::from_str(user.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get user", err);
            RCString::null()
        }
    }
}

/// Updates an IAM user.
///
/// user: IAM User to be updated
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_user(
    management_client: *mut ManagementClient,
    user: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user = user.to_string();
        let user: objectscale_client::iam::User =
            serde_json::from_str(&user).expect("deserialize user");

        management_client.management_client.update_user(user)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update user", err);
            false
        }
    }
}

/// Delete specified IAM User.
///
/// user_name: The name of the user to delete. Cannot be empty.
/// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_user(
    management_client: *mut ManagementClient,
    user_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_name = user_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .delete_user(&user_name, &namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete user", err);
        }
    }
}

/// Lists the IAM users.
///
/// namespace: Namespace of users(id of the account the user belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_users(
    management_client: *mut ManagementClient,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();

        management_client.management_client.list_users(&namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|users| serde_yaml::to_string(&users).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(users) => RCString::from_str(users.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list users", err);
            RCString::null()
        }
    }
}

/// Attaches the specified managed policy to the specified user.
///
/// user_policy_attachment: UserPolicyAttachment to create
///
/// PS: attach the same policy would throw error
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_user_policy_attachment(
    management_client: *mut ManagementClient,
    user_policy_attachment: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_policy_attachment = user_policy_attachment.to_string();
        let user_policy_attachment: objectscale_client::iam::UserPolicyAttachment =
            serde_json::from_str(&user_policy_attachment)
                .expect("deserialize user_policy_attachment");

        management_client
            .management_client
            .create_user_policy_attachment(user_policy_attachment)
    })) {
        Ok(result) => {
            let result = result.and_then(|user_policy_attachment| {
                serde_yaml::to_string(&user_policy_attachment).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_policy_attachment) => RCString::from_str(user_policy_attachment.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create user policy attachment", err);
            RCString::null()
        }
    }
}

/// Remove the specified managed policy attached to the specified user.
///
/// user_policy_attachment: UserPolicyAttachment to delete.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_user_policy_attachment(
    management_client: *mut ManagementClient,
    user_policy_attachment: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_policy_attachment = user_policy_attachment.to_string();
        let user_policy_attachment: objectscale_client::iam::UserPolicyAttachment =
            serde_json::from_str(&user_policy_attachment)
                .expect("deserialize user_policy_attachment");

        management_client
            .management_client
            .delete_user_policy_attachment(user_policy_attachment)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete user policy attachment", err);
        }
    }
}

/// Lists all managed policies that are attached to the specified IAM user.
///
/// user_name: The name of the user to list attached policies for. Cannot be empty.
/// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_user_policy_attachments(
    management_client: *mut ManagementClient,
    user_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_name = user_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_user_policy_attachments(&user_name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|user_policy_attachments| {
                serde_yaml::to_string(&user_policy_attachments).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_policy_attachments) => RCString::from_str(user_policy_attachments.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list user policy attachments", err);
            RCString::null()
        }
    }
}

/// Creates AccessKey for user.
///
/// access_key: AccessKey to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_access_key(
    management_client: *mut ManagementClient,
    access_key: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let access_key = access_key.to_string();
        let access_key: objectscale_client::iam::AccessKey =
            serde_json::from_str(&access_key).expect("deserialize access_key");

        management_client
            .management_client
            .create_access_key(access_key)
    })) {
        Ok(result) => {
            let result = result
                .and_then(|access_key| serde_yaml::to_string(&access_key).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(access_key) => RCString::from_str(access_key.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create access key", err);
            RCString::null()
        }
    }
}

/// Updates AccessKey for user.
///
/// access_key: AccessKey to update
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_access_key(
    management_client: *mut ManagementClient,
    access_key: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let access_key = access_key.to_string();
        let access_key: objectscale_client::iam::AccessKey =
            serde_json::from_str(&access_key).expect("deserialize access_key");

        management_client
            .management_client
            .update_access_key(access_key)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update access key", err);
            false
        }
    }
}

/// Deletes the access key pair associated with the specified IAM user.
///
/// access_key_id: The ID of the access key you want to delete. Cannot be empty.
/// user_name: Name of the user to delete accesskeys. Cannot be empty.
/// namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_access_key(
    management_client: *mut ManagementClient,
    access_key_id: RCString,
    user_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let access_key_id = access_key_id.to_string();
        let user_name = user_name.to_string();
        let namespace = namespace.to_string();

        management_client.management_client.delete_access_key(
            &access_key_id,
            &user_name,
            &namespace,
        )
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete access key", err);
        }
    }
}

/// Returns information about the access key IDs associated with the specified IAM user.
///
/// user_name: Name of the user to list accesskeys. Cannot be empty.
/// namespace: Namespace of the access key(id of the account the access key belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_access_keys(
    management_client: *mut ManagementClient,
    user_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_name = user_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_access_keys(&user_name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|access_keys| {
                serde_yaml::to_string(&access_keys).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(access_keys) => RCString::from_str(access_keys.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list access keys", err);
            RCString::null()
        }
    }
}

/// Create a new Managed Policy.
///
/// policy: IAM Policy to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_policy(
    management_client: *mut ManagementClient,
    policy: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let policy = policy.to_string();
        let policy: objectscale_client::iam::Policy =
            serde_json::from_str(&policy).expect("deserialize policy");

        management_client.management_client.create_policy(policy)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|policy| serde_yaml::to_string(&policy).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(policy) => RCString::from_str(policy.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create policy", err);
            RCString::null()
        }
    }
}

/// Retrieve information about the specified Managed Policy.
///
/// policy_arn: Arn of the policy to retrieve. Cannot be empty.
/// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_policy(
    management_client: *mut ManagementClient,
    policy_arn: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let policy_arn = policy_arn.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .get_policy(&policy_arn, &namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|policy| serde_yaml::to_string(&policy).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(policy) => RCString::from_str(policy.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get policy", err);
            RCString::null()
        }
    }
}

/// Delete the specified Managed Policy.
///
/// policy_arn: Arn of the policy to delete. Cannot be empty.
/// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_policy(
    management_client: *mut ManagementClient,
    policy_arn: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let policy_arn = policy_arn.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .delete_policy(&policy_arn, &namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete policy", err);
        }
    }
}

/// Lists IAM Managed Policies.
///
/// namespace: Namespace of the policies(id of the account policies belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_policies(
    management_client: *mut ManagementClient,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_policies(&namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|policys| serde_yaml::to_string(&policys).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(policys) => RCString::from_str(policys.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list policies", err);
            RCString::null()
        }
    }
}

/// Creates a new IAM Group.
///
/// group: IAM Group to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_group(
    management_client: *mut ManagementClient,
    group: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let group = group.to_string();
        let group: objectscale_client::iam::Group =
            serde_json::from_str(&group).expect("deserialize group");

        management_client.management_client.create_group(group)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|group| serde_yaml::to_string(&group).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(group) => RCString::from_str(group.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create group", err);
            RCString::null()
        }
    }
}

/// Returns the information about the specified IAM Group.
///
/// group_name: The name of the group to retrieve. Cannot be empty.
/// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_group(
    management_client: *mut ManagementClient,
    group_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let group_name = group_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .get_group(&group_name, &namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|group| serde_yaml::to_string(&group).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(group) => RCString::from_str(group.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get group", err);
            RCString::null()
        }
    }
}

/// Delete specified IAM User.
///
/// group_name: The name of the group to delete. Cannot be empty.
/// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_group(
    management_client: *mut ManagementClient,
    group_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let group_name = group_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .delete_group(&group_name, &namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete group", err);
        }
    }
}

/// Lists the IAM groups.
///
/// namespace: Namespace of groups(id of the account groups belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_groups(
    management_client: *mut ManagementClient,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();

        management_client.management_client.list_groups(&namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|groups| serde_yaml::to_string(&groups).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(groups) => RCString::from_str(groups.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list groups", err);
            RCString::null()
        }
    }
}

/// Attaches the specified managed policy to the specified group.
///
/// group_policy_attachment: GroupPolicyAttachment to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_group_policy_attachment(
    management_client: *mut ManagementClient,
    group_policy_attachment: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let group_policy_attachment = group_policy_attachment.to_string();
        let group_policy_attachment: objectscale_client::iam::GroupPolicyAttachment =
            serde_json::from_str(&group_policy_attachment)
                .expect("deserialize group_policy_attachment");

        management_client
            .management_client
            .create_group_policy_attachment(group_policy_attachment)
    })) {
        Ok(result) => {
            let result = result.and_then(|group_policy_attachment| {
                serde_yaml::to_string(&group_policy_attachment).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(group_policy_attachment) => RCString::from_str(group_policy_attachment.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create group policy attachment", err);
            RCString::null()
        }
    }
}

/// Remove the specified managed policy attached to the specified group.
///
/// group_policy_attachment: GroupPolicyAttachment to delete.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_group_policy_attachment(
    management_client: *mut ManagementClient,
    group_policy_attachment: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let group_policy_attachment = group_policy_attachment.to_string();
        let group_policy_attachment: objectscale_client::iam::GroupPolicyAttachment =
            serde_json::from_str(&group_policy_attachment)
                .expect("deserialize group_policy_attachment");

        management_client
            .management_client
            .delete_group_policy_attachment(group_policy_attachment)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete group policy attachment", err);
        }
    }
}

/// Lists all managed policies that are attached to the specified IAM Group.
///
/// group_name: The name of the group to list attached policies for. Cannot be empty.
/// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_group_policy_attachments(
    management_client: *mut ManagementClient,
    group_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let group_name = group_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_group_policy_attachments(&group_name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|group_policy_attachments| {
                serde_yaml::to_string(&group_policy_attachments).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(group_policy_attachments) => {
                    RCString::from_str(group_policy_attachments.as_str())
                }
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list group policy attachments", err);
            RCString::null()
        }
    }
}

/// Creates a new IAM Role.
///
/// role: IAM Role to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_role(
    management_client: *mut ManagementClient,
    role: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role = role.to_string();
        let role: objectscale_client::iam::Role =
            serde_json::from_str(&role).expect("deserialize role");

        management_client.management_client.create_role(role)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|role| serde_yaml::to_string(&role).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(role) => RCString::from_str(role.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create role", err);
            RCString::null()
        }
    }
}

/// Returns the information about the specified IAM Role.
///
/// role_name: The name of the role to retrieve. Cannot be empty.
/// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_role(
    management_client: *mut ManagementClient,
    role_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role_name = role_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .get_role(&role_name, &namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|role| serde_yaml::to_string(&role).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(role) => RCString::from_str(role.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get role", err);
            RCString::null()
        }
    }
}

/// Updates a new IAM Role.
///
/// role: IAM Role to update
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_role(
    management_client: *mut ManagementClient,
    role: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role = role.to_string();
        let role: objectscale_client::iam::Role =
            serde_json::from_str(&role).expect("deserialize role");

        management_client.management_client.update_role(role)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update role", err);
            false
        }
    }
}

/// Delete specified IAM Role.
///
/// role_name: The name of the role to delete. Cannot be empty.
/// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_role(
    management_client: *mut ManagementClient,
    role_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role_name = role_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .delete_role(&role_name, &namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete role", err);
        }
    }
}

/// Lists the IAM roles.
///
/// namespace: Namespace of roles(id of the account roles belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_roles(
    management_client: *mut ManagementClient,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();

        management_client.management_client.list_roles(&namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|roles| serde_yaml::to_string(&roles).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(roles) => RCString::from_str(roles.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list roles", err);
            RCString::null()
        }
    }
}

/// Attaches the specified managed policy to the specified role.
///
/// role_policy_attachment: RolePolicyAttachment to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_role_policy_attachment(
    management_client: *mut ManagementClient,
    role_policy_attachment: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role_policy_attachment = role_policy_attachment.to_string();
        let role_policy_attachment: objectscale_client::iam::RolePolicyAttachment =
            serde_json::from_str(&role_policy_attachment)
                .expect("deserialize role_policy_attachment");

        management_client
            .management_client
            .create_role_policy_attachment(role_policy_attachment)
    })) {
        Ok(result) => {
            let result = result.and_then(|role_policy_attachment| {
                serde_yaml::to_string(&role_policy_attachment).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(role_policy_attachment) => RCString::from_str(role_policy_attachment.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create role policy attachment", err);
            RCString::null()
        }
    }
}

/// Remove the specified managed policy attached to the specified role.
///
/// role_policy_attachment: RolePolicyAttachment to delete.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_role_policy_attachment(
    management_client: *mut ManagementClient,
    role_policy_attachment: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role_policy_attachment = role_policy_attachment.to_string();
        let role_policy_attachment: objectscale_client::iam::RolePolicyAttachment =
            serde_json::from_str(&role_policy_attachment)
                .expect("deserialize role_policy_attachment");

        management_client
            .management_client
            .delete_role_policy_attachment(role_policy_attachment)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete role policy attachment", err);
        }
    }
}

/// Lists all managed policies that are attached to the specified IAM Role.
///
/// role_name: The name of the role to list attached policies for. Cannot be empty.
/// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_role_policy_attachments(
    management_client: *mut ManagementClient,
    role_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role_name = role_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_role_policy_attachments(&role_name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|role_policy_attachments| {
                serde_yaml::to_string(&role_policy_attachments).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(role_policy_attachments) => RCString::from_str(role_policy_attachments.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list role policy attachments", err);
            RCString::null()
        }
    }
}

/// Lists all IAM users, groups, and roles that the specified managed policy is attached to.
///
/// policy_arn: Arn of the policy to list entities for. Cannot be empty.
/// namespace: Namespace of the policy(id of the account the policy belongs to). Cannot be empty.
/// entity_filter: The entity type to use for filtering the results. Valid values: User, Role, Group.
/// usage_filter: The policy usage method to use for filtering the results. Valid values: PermissionsPolicy, PermissionsBoundary.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_entities_for_policy(
    management_client: *mut ManagementClient,
    policy_arn: RCString,
    namespace: RCString,
    entity_filter: RCString,
    usage_filter: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let policy_arn = policy_arn.to_string();
        let namespace = namespace.to_string();
        let entity_filter = entity_filter.to_string();
        let usage_filter = usage_filter.to_string();

        management_client.management_client.get_entities_for_policy(
            &policy_arn,
            &namespace,
            &entity_filter,
            &usage_filter,
        )
    })) {
        Ok(result) => {
            let result = result.and_then(|entities_for_policy| {
                serde_yaml::to_string(&entities_for_policy).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(entities_for_policy) => RCString::from_str(entities_for_policy.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get entities for policy", err);
            RCString::null()
        }
    }
}

/// Adds the specified user to the specified group.
///
/// user_group_membership: UserGroupMembership to create.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_user_group_membership(
    management_client: *mut ManagementClient,
    user_group_membership: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_group_membership = user_group_membership.to_string();
        let user_group_membership: objectscale_client::iam::UserGroupMembership =
            serde_json::from_str(&user_group_membership)
                .expect("deserialize user_group_membership");

        management_client
            .management_client
            .create_user_group_membership(user_group_membership)
    })) {
        Ok(result) => {
            let result = result.and_then(|user_group_membership| {
                serde_yaml::to_string(&user_group_membership).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_group_membership) => RCString::from_str(user_group_membership.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create user group membership", err);
            RCString::null()
        }
    }
}

/// Removes the specified user from the specified group.
///
/// user_group_membership: GroupPolicyAttachment to delete.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_user_group_membership(
    management_client: *mut ManagementClient,
    user_group_membership: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_group_membership = user_group_membership.to_string();
        let user_group_membership: objectscale_client::iam::UserGroupMembership =
            serde_json::from_str(&user_group_membership)
                .expect("deserialize user_group_membership");

        management_client
            .management_client
            .delete_user_group_membership(user_group_membership)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete user group membership", err);
        }
    }
}

/// Lists the IAM groups that the specified IAM user belongs to.
///
/// user_name: The name of the user to list group membership for. Cannot be empty.
/// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_user_group_memberships_by_user(
    management_client: *mut ManagementClient,
    user_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user_name = user_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_user_group_memberships_by_user(&user_name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|user_group_memberships| {
                serde_yaml::to_string(&user_group_memberships).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_group_memberships) => RCString::from_str(user_group_memberships.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error(
                "caught panic during list user group memberships by user",
                err,
            );
            RCString::null()
        }
    }
}

/// Create SAML Identity Provider
///
/// provider: SAML provider to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_saml_provider(
    management_client: *mut ManagementClient,
    provider: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let provider = provider.to_string();
        let provider: objectscale_client::iam::SamlProvider =
            serde_json::from_str(&provider).expect("deserialize provider");

        management_client
            .management_client
            .create_saml_provider(provider)
    })) {
        Ok(result) => {
            let result = result.and_then(|saml_provider| {
                serde_yaml::to_string(&saml_provider).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(saml_provider) => RCString::from_str(saml_provider.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create saml provider", err);
            RCString::null()
        }
    }
}

/// Retrieve the SAML IdP document.
///
/// arn: The name of the provider to retrieve.
/// namespace: Namespace of the role(id of the account the role belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_saml_provider(
    management_client: *mut ManagementClient,
    arn: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let arn = arn.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .get_saml_provider(&arn, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|saml_provider| {
                serde_yaml::to_string(&saml_provider).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(saml_provider) => RCString::from_str(saml_provider.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get saml provider", err);
            RCString::null()
        }
    }
}

/// Update the SAML Identity Provider.
///
/// role: SAML Identity Provider to update
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_saml_provider(
    management_client: *mut ManagementClient,
    provider: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let provider = provider.to_string();
        let provider: objectscale_client::iam::SamlProvider =
            serde_json::from_str(&provider).expect("deserialize provider");

        management_client
            .management_client
            .update_saml_provider(provider)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update saml provider", err);
            false
        }
    }
}

/// Delete the SAML Identity Provider.
///
/// arn: The ARN of the provider to delete.
/// namespace: ECS namespace IAM entity belongs to
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_saml_provider(
    management_client: *mut ManagementClient,
    arn: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let arn = arn.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .delete_saml_provider(&arn, &namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete saml provider", err);
        }
    }
}

/// List the SAML Identity Providers.
///
/// namespace: ECS namespace IAM entity belongs to
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_saml_providers(
    management_client: *mut ManagementClient,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_saml_providers(&namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|saml_providers| {
                serde_yaml::to_string(&saml_providers).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(saml_providers) => RCString::from_str(saml_providers.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list saml providers", err);
            RCString::null()
        }
    }
}

/// Lists the IAM users that the specified IAM group contains.
///
/// group_name: The name of the group to list contained users for. Cannot be empty.
/// namespace: Namespace of the group(id of the account the group belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_user_group_memberships_by_group(
    management_client: *mut ManagementClient,
    group_name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let group_name = group_name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .list_user_group_memberships_by_group(&group_name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|user_group_memberships| {
                serde_yaml::to_string(&user_group_memberships).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_group_memberships) => RCString::from_str(user_group_memberships.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error(
                "caught panic during list user group memberships by group",
                err,
            );
            RCString::null()
        }
    }
}

/// Gets the list of buckets for the specified namespace.
///
/// namespace: Namespace for which buckets should be listed. Cannot be empty.
/// name_prefix: Case sensitive prefix of the Bucket name with a wild card(*). Can be empty or any_prefix_string*.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_buckets(
    management_client: *mut ManagementClient,
    namespace: RCString,
    name_prefix: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();
        let name_prefix = name_prefix.to_string();

        management_client
            .management_client
            .list_buckets(&namespace, &name_prefix)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|buckets| serde_yaml::to_string(&buckets).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(buckets) => RCString::from_str(buckets.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list buckets", err);
            RCString::null()
        }
    }
}

/// Create an bucket.
///
/// bucket: Bucket to create.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_bucket(
    management_client: *mut ManagementClient,
    bucket: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let bucket = bucket.to_string();
        let bucket: objectscale_client::provisioning::Bucket =
            serde_json::from_str(&bucket).expect("deserialize bucket");

        management_client.management_client.create_bucket(bucket)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|bucket| serde_yaml::to_string(&bucket).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(bucket) => RCString::from_str(bucket.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create bucket", err);
            RCString::null()
        }
    }
}

/// Gets bucket information for the specified bucket.
///
/// name: Bucket name for which information will be retrieved. Cannot be empty.
/// namespace: Namespace associated. Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_bucket(
    management_client: *mut ManagementClient,
    name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .get_bucket(&name, &namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|bucket| serde_yaml::to_string(&bucket).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(bucket) => RCString::from_str(bucket.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get bucket", err);
            RCString::null()
        }
    }
}

/// Update an bucket.
///
/// bucket: Bucket to update.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_bucket(
    management_client: *mut ManagementClient,
    bucket: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let bucket = bucket.to_string();
        let bucket: objectscale_client::provisioning::Bucket =
            serde_json::from_str(&bucket).expect("deserialize bucket");

        management_client.management_client.update_bucket(bucket)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update bucket", err);
            false
        }
    }
}

/// Deletes the specified bucket.
///
/// name: Bucket name to be deleted. Cannot be empty.
/// namespace: Namespace associated. Cannot be empty.
/// emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_bucket(
    management_client: *mut ManagementClient,
    name: RCString,
    namespace: RCString,
    empty_bucket: bool,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .delete_bucket(&name, &namespace, empty_bucket)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete bucket", err);
        }
    }
}

/// Creates a namespace with the given details.
///
/// namespace: Namespace to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_namespace(
    management_client: *mut ManagementClient,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();
        let namespace: objectscale_client::tenancy::Namespace =
            serde_json::from_str(&namespace).expect("deserialize namespace");

        management_client
            .management_client
            .create_namespace(namespace)
    })) {
        Ok(result) => {
            let result = result
                .and_then(|namespace| serde_yaml::to_string(&namespace).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(namespace) => RCString::from_str(namespace.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create namespace", err);
            RCString::null()
        }
    }
}

/// Gets the details for the given namespace.
///
/// id: Namespace identifier for which details needs to be retrieved.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_namespace(
    management_client: *mut ManagementClient,
    id: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let id = id.to_string();

        management_client.management_client.get_namespace(&id)
    })) {
        Ok(result) => {
            let result = result
                .and_then(|namespace| serde_yaml::to_string(&namespace).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(namespace) => RCString::from_str(namespace.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get namespace", err);
            RCString::null()
        }
    }
}

/// Update a namespace with the given details.
///
/// namespace: Namespace to be updated
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_namespace(
    management_client: *mut ManagementClient,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();
        let namespace: objectscale_client::tenancy::Namespace =
            serde_json::from_str(&namespace).expect("deserialize namespace");

        management_client
            .management_client
            .update_namespace(namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update namespace", err);
            false
        }
    }
}

/// Deactivates and deletes the given namespace and all associated user mappings.
///
/// id: An active namespace identifier which needs to be deactivated/deleted
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_namespace(
    management_client: *mut ManagementClient,
    id: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let id = id.to_string();

        management_client.management_client.delete_namespace(&id)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete namespace", err);
        }
    }
}

/// Gets the list of all configured namespaces.
///
/// name_prefix: Case sensitive prefix of the Namespace name with a wild card(*) Ex : any_prefix_string*.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_namespaces(
    management_client: *mut ManagementClient,
    name_prefix: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name_prefix = name_prefix.to_string();

        management_client
            .management_client
            .list_namespaces(&name_prefix)
    })) {
        Ok(result) => {
            let result = result
                .and_then(|namespaces| serde_yaml::to_string(&namespaces).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(namespaces) => RCString::from_str(namespaces.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list namespaces", err);
            RCString::null()
        }
    }
}

/// Creates local users for the VDC.
///
/// user: ManagementUser to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_management_user(
    management_client: *mut ManagementClient,
    user: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user = user.to_string();
        let user: objectscale_client::user::ManagementUser =
            serde_json::from_str(&user).expect("deserialize user");

        management_client
            .management_client
            .create_management_user(user)
    })) {
        Ok(result) => {
            let result = result.and_then(|management_user| {
                serde_yaml::to_string(&management_user).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(management_user) => RCString::from_str(management_user.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create management user", err);
            RCString::null()
        }
    }
}

/// Gets details for the specified local management user.
///
/// id: User identifier for which local user information needs to be retrieved
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_management_user(
    management_client: *mut ManagementClient,
    id: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let id = id.to_string();

        management_client.management_client.get_management_user(&id)
    })) {
        Ok(result) => {
            let result = result.and_then(|management_user| {
                serde_yaml::to_string(&management_user).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(management_user) => RCString::from_str(management_user.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get management user", err);
            RCString::null()
        }
    }
}

/// Updates user details for the specified local management user.
///
/// user: ManagementUser to be updated
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_management_user(
    management_client: *mut ManagementClient,
    user: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user = user.to_string();
        let user: objectscale_client::user::ManagementUser =
            serde_json::from_str(&user).expect("deserialize user");

        management_client
            .management_client
            .update_management_user(user)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update management user", err);
            false
        }
    }
}

/// Deletes local management user information for the specified user identifier.
///
/// id: User identifier for which local user information needs to be deleted.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_management_user(
    management_client: *mut ManagementClient,
    id: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let id = id.to_string();

        management_client
            .management_client
            .delete_management_user(&id)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete management user", err);
        }
    }
}

/// Gets all configured local management users.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_management_users(
    management_client: *mut ManagementClient,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        management_client.management_client.list_management_users()
    })) {
        Ok(result) => {
            let result = result.and_then(|management_users| {
                serde_yaml::to_string(&management_users).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(management_users) => RCString::from_str(management_users.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list management users", err);
            RCString::null()
        }
    }
}

/// Creates a user for a specified namespace.
///
/// user: ObjectUser to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_object_user(
    management_client: *mut ManagementClient,
    user: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user = user.to_string();
        let user: objectscale_client::user::ObjectUser =
            serde_json::from_str(&user).expect("deserialize user");

        management_client.management_client.create_object_user(user)
    })) {
        Ok(result) => {
            let result = result.and_then(|object_user| {
                serde_yaml::to_string(&object_user).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(object_user) => RCString::from_str(object_user.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create object user", err);
            RCString::null()
        }
    }
}

/// Gets user details for the specified user belong to the specified namespace.
///
/// name: Valid user identifier
/// namespace: The namespace to which user belong
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_object_user(
    management_client: *mut ManagementClient,
    name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .get_object_user(&name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|object_user| {
                serde_yaml::to_string(&object_user).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(object_user) => RCString::from_str(object_user.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get object user", err);
            RCString::null()
        }
    }
}

/// Updates user details for the specified object user.
///
/// user: ObjectUser to be updated
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_object_user(
    management_client: *mut ManagementClient,
    user: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let user = user.to_string();
        let user: objectscale_client::user::ObjectUser =
            serde_json::from_str(&user).expect("deserialize user");

        management_client.management_client.update_object_user(user)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update object user", err);
            false
        }
    }
}

/// Deletes the specified user and its secret keys.
///
/// name: User to be deleted.
/// namespace: Namespace identifier to associate with the user
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_object_user(
    management_client: *mut ManagementClient,
    name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();
        let namespace = namespace.to_string();

        management_client
            .management_client
            .delete_object_user(&name, &namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete object user", err);
        }
    }
}

/// Gets identifiers for all configured users.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_object_users(
    management_client: *mut ManagementClient,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        management_client.management_client.list_object_users()
    })) {
        Ok(result) => {
            let result = result.and_then(|object_users| {
                serde_yaml::to_string(&object_users).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(object_users) => RCString::from_str(object_users.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list object users", err);
            RCString::null()
        }
    }
}

/// Get the certificate chain being used by ECS
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_vdc_keystore(
    management_client: *mut ManagementClient,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        management_client.management_client.get_vdc_keystore()
    })) {
        Ok(result) => {
            let result = result.and_then(|vdc_keystore| {
                serde_yaml::to_string(&vdc_keystore).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(vdc_keystore) => RCString::from_str(vdc_keystore.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get vdc keystore", err);
            RCString::null()
        }
    }
}

/// Set the certificate chain being used by ECS.
///
/// keystore: VdcKeystore to be updated
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_vdc_keystore(
    management_client: *mut ManagementClient,
    keystore: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let keystore = keystore.to_string();
        let keystore: objectscale_client::provisioning::VdcKeystore =
            serde_json::from_str(&keystore).expect("deserialize keystore");

        management_client
            .management_client
            .update_vdc_keystore(keystore)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update vdc keystore", err);
            false
        }
    }
}

/// Gets the details for a VDC the identify of which is specified by its name.
///
/// name: VDC name for which VDC Information is to be retrieved
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_vdc(
    management_client: *mut ManagementClient,
    name: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();

        management_client.management_client.get_vdc(&name)
    })) {
        Ok(result) => {
            let result = result.and_then(|vdc| serde_yaml::to_string(&vdc).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(vdc) => RCString::from_str(vdc.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get vdc", err);
            RCString::null()
        }
    }
}

/// Deactivates and deletes a VDC.
///
/// id: VDC identifier for which VDC Information needs to be deleted
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_vdc(
    management_client: *mut ManagementClient,
    id: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let id = id.to_string();

        management_client.management_client.delete_vdc(&id)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete vdc", err);
        }
    }
}

/// Gets all details of all configured VDCs.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_vdcs(
    management_client: *mut ManagementClient,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        management_client.management_client.list_vdcs()
    })) {
        Ok(result) => {
            let result =
                result.and_then(|vdcs| serde_yaml::to_string(&vdcs).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(vdcs) => RCString::from_str(vdcs.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list vdcs", err);
            RCString::null()
        }
    }
}

/// Gets the details for the specified storage pool.
///
/// id: Storage pool identifier to be retrieved
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_storage_pool(
    management_client: *mut ManagementClient,
    id: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let id = id.to_string();

        management_client.management_client.get_storage_pool(&id)
    })) {
        Ok(result) => {
            let result = result.and_then(|storage_pool| {
                serde_yaml::to_string(&storage_pool).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(storage_pool) => RCString::from_str(storage_pool.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get storage pool", err);
            RCString::null()
        }
    }
}

/// Updates storage pool for the specified identifier..
///
/// sp: Storage pool to be updated
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_storage_pool(
    management_client: *mut ManagementClient,
    sp: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let sp = sp.to_string();
        let sp: objectscale_client::provisioning::StoragePool =
            serde_json::from_str(&sp).expect("deserialize sp");

        management_client.management_client.update_storage_pool(sp)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update storage pool", err);
            false
        }
    }
}

/// Gets a list of storage pools from the local VDC.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_storage_pools(
    management_client: *mut ManagementClient,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        management_client.management_client.list_storage_pools()
    })) {
        Ok(result) => {
            let result = result.and_then(|storage_pools| {
                serde_yaml::to_string(&storage_pools).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(storage_pools) => RCString::from_str(storage_pools.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list storage pools", err);
            RCString::null()
        }
    }
}

/// Creates a replication group that includes the specified storage pools
///
/// rg: ReplicationGroup to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_replication_group(
    management_client: *mut ManagementClient,
    rg: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let rg = rg.to_string();
        let rg: objectscale_client::replication::ReplicationGroup =
            serde_json::from_str(&rg).expect("deserialize rg");

        management_client
            .management_client
            .create_replication_group(rg)
    })) {
        Ok(result) => {
            let result = result.and_then(|replication_group| {
                serde_yaml::to_string(&replication_group).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(replication_group) => RCString::from_str(replication_group.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create replication group", err);
            RCString::null()
        }
    }
}

/// Gets the details for the specified replication group.
///
/// id: Replication group identifier for which details needs to be retrieved
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_replication_group(
    management_client: *mut ManagementClient,
    id: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let id = id.to_string();

        management_client
            .management_client
            .get_replication_group(&id)
    })) {
        Ok(result) => {
            let result = result.and_then(|replication_group| {
                serde_yaml::to_string(&replication_group).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(replication_group) => RCString::from_str(replication_group.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get replication group", err);
            RCString::null()
        }
    }
}

/// Updates the name and description for a replication group.
///
/// rg: Replication group which details needs to be updated
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_replication_group(
    management_client: *mut ManagementClient,
    rg: RCString,
    err: Option<&mut RCString>,
) -> bool {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let rg = rg.to_string();
        let rg: objectscale_client::replication::ReplicationGroup =
            serde_json::from_str(&rg).expect("deserialize rg");

        management_client
            .management_client
            .update_replication_group(rg)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(state) => return state,
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    false
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update replication group", err);
            false
        }
    }
}

/// Lists all configured replication groups.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_replication_groups(
    management_client: *mut ManagementClient,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        management_client
            .management_client
            .list_replication_groups()
    })) {
        Ok(result) => {
            let result = result.and_then(|replication_groups| {
                serde_yaml::to_string(&replication_groups).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(replication_groups) => RCString::from_str(replication_groups.as_str()),
                Err(e) => {
                    set_error(&format!("{:?}", e), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list replication groups", err);
            RCString::null()
        }
    }
}
