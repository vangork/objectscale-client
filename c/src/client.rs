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
                    set_error(e.to_string().as_str(), err);
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

#[no_mangle]
pub unsafe extern "C" fn management_client_new_objectstore_client(
    management_client: *mut ManagementClient,
    endpoint: RCString,
    err: Option<&mut RCString>,
) -> *mut ObjectstoreClient {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let endpoint = endpoint.to_string();

        management_client
            .management_client
            .new_objectstore_client(&endpoint)
    })) {
        Ok(result) => {
            clear_error();
            clear_error();
            match result {
                Ok(objectstore_client) => {
                    Box::into_raw(Box::new(ObjectstoreClient { objectstore_client }))
                }
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    ptr::null_mut()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during new objectstore client", err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn destroy_objectstore_client(objectstore_client: *mut ObjectstoreClient) {
    if !objectstore_client.is_null() {
        unsafe {
            drop(Box::from_raw(objectstore_client));
        }
    }
}

/// Create an IAM account.
///
/// account: Iam Account to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_account(
    management_client: *mut ManagementClient,
    account: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account = account.to_string();
        let account: objectscale_client::iam::Account =
            serde_json::from_str(&account).expect("deserialize account");

        management_client.management_client.create_account(account)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|account| serde_json::to_string(&account).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(account) => RCString::from_str(account.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create account", err);
            RCString::null()
        }
    }
}

/// Get an IAM account.
///
/// account_id: Id of the account
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_account(
    management_client: *mut ManagementClient,
    account_id: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_id = account_id.to_string();

        management_client.management_client.get_account(&account_id)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|account| serde_json::to_string(&account).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(account) => RCString::from_str(account.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get account", err);
            RCString::null()
        }
    }
}

/// Update an IAM account.
///
/// account: Iam Account to update
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_account(
    management_client: *mut ManagementClient,
    account: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account = account.to_string();
        let account: objectscale_client::iam::Account =
            serde_json::from_str(&account).expect("deserialize account");

        management_client.management_client.update_account(account)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|account| serde_json::to_string(&account).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(account) => RCString::from_str(account.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update account", err);
            RCString::null()
        }
    }
}

/// Delete an IAM account.
///
/// account_id: Id of the account
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_account(
    management_client: *mut ManagementClient,
    account_id: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_id = account_id.to_string();

        management_client
            .management_client
            .delete_account(&account_id)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete account", err);
        }
    }
}

/// List all IAM accounts.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_accounts(
    management_client: *mut ManagementClient,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        management_client.management_client.list_accounts()
    })) {
        Ok(result) => {
            let result = result
                .and_then(|accounts| serde_json::to_string(&accounts).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(accounts) => RCString::from_str(accounts.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list accounts", err);
            RCString::null()
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
                result.and_then(|user| serde_json::to_string(&user).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(user) => RCString::from_str(user.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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

/// Returns the information about the specified IAM User.
///
/// user_name: The name of the user to retrieve. Cannot be empty.
/// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_user(
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
            .get_user(&user_name, &namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|user| serde_json::to_string(&user).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(user) => RCString::from_str(user.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                    set_error(e.to_string().as_str(), err);
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
/// TODO:
/// list_user won't show tags, or permissions boundary if any
/// fix it or report bug
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
                result.and_then(|users| serde_json::to_string(&users).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(users) => RCString::from_str(users.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&user_policy_attachment).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_policy_attachment) => RCString::from_str(user_policy_attachment.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&user_policy_attachments).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_policy_attachments) => RCString::from_str(user_policy_attachments.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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

/// Creates a password for the specified IAM user.
///
/// login_profile: LoginProfile to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_login_profile(
    management_client: *mut ManagementClient,
    login_profile: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let login_profile = login_profile.to_string();
        let login_profile: objectscale_client::iam::LoginProfile =
            serde_json::from_str(&login_profile).expect("deserialize login_profile");

        management_client
            .management_client
            .create_login_profile(login_profile)
    })) {
        Ok(result) => {
            let result = result.and_then(|login_profile| {
                serde_json::to_string(&login_profile).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(login_profile) => RCString::from_str(login_profile.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create login profile", err);
            RCString::null()
        }
    }
}

/// Retrieves the password for the specified IAM user
///
/// user_name: Name of the user to delete password. Cannot be empty.
/// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_get_login_profile(
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
            .get_login_profile(&user_name, &namespace)
    })) {
        Ok(result) => {
            let result = result.and_then(|login_profile| {
                serde_json::to_string(&login_profile).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(login_profile) => RCString::from_str(login_profile.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get login profile", err);
            RCString::null()
        }
    }
}

/// Deletes the password for the specified IAM user
///
/// user_name: Name of the user to delete password. Cannot be empty.
/// namespace: Namespace of the user(id of the account the user belongs to). Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_login_profile(
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
            .delete_login_profile(&user_name, &namespace)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete login profile", err);
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
                .and_then(|access_key| serde_json::to_string(&access_key).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(access_key) => RCString::from_str(access_key.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
) -> RCString {
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
            let result = result
                .and_then(|access_key| serde_json::to_string(&access_key).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(access_key) => RCString::from_str(access_key.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update access key", err);
            RCString::null()
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
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&access_keys).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(access_keys) => RCString::from_str(access_keys.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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

/// Creates account AccessKey.
///
/// account_access_key: Account Access Key to create
///
#[no_mangle]
pub unsafe extern "C" fn management_client_create_account_access_key(
    management_client: *mut ManagementClient,
    account_access_key: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_access_key = account_access_key.to_string();
        let account_access_key: objectscale_client::iam::AccountAccessKey =
            serde_json::from_str(&account_access_key).expect("deserialize account_access_key");

        management_client
            .management_client
            .create_account_access_key(account_access_key)
    })) {
        Ok(result) => {
            let result = result.and_then(|account_access_key| {
                serde_json::to_string(&account_access_key).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(account_access_key) => RCString::from_str(account_access_key.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create account access key", err);
            RCString::null()
        }
    }
}

/// Updates account AccessKey.
///
/// account_access_key: Account Access Key to update
///
#[no_mangle]
pub unsafe extern "C" fn management_client_update_account_access_key(
    management_client: *mut ManagementClient,
    account_access_key: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_access_key = account_access_key.to_string();
        let account_access_key: objectscale_client::iam::AccountAccessKey =
            serde_json::from_str(&account_access_key).expect("deserialize account_access_key");

        management_client
            .management_client
            .update_account_access_key(account_access_key)
    })) {
        Ok(result) => {
            let result = result.and_then(|account_access_key| {
                serde_json::to_string(&account_access_key).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(account_access_key) => RCString::from_str(account_access_key.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update account access key", err);
            RCString::null()
        }
    }
}

/// Deletes the access key pair associated with the specified IAM account.
///
/// access_key_id: The ID of the access key. Cannot be empty.
/// account_id: The id of the account. Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_delete_account_access_key(
    management_client: *mut ManagementClient,
    access_key_id: RCString,
    account_id: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let access_key_id = access_key_id.to_string();
        let account_id = account_id.to_string();

        management_client
            .management_client
            .delete_account_access_key(&access_key_id, &account_id)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete account access key", err);
        }
    }
}

/// Returns information about the access key IDs associated with the specified IAM account.
///
/// account_id: The id of the account. Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn management_client_list_account_access_keys(
    management_client: *mut ManagementClient,
    account_id: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_id = account_id.to_string();

        management_client
            .management_client
            .list_account_access_keys(&account_id)
    })) {
        Ok(result) => {
            let result = result.and_then(|account_access_keys| {
                serde_json::to_string(&account_access_keys).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(account_access_keys) => RCString::from_str(account_access_keys.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list account access keys", err);
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
                result.and_then(|policy| serde_json::to_string(&policy).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(policy) => RCString::from_str(policy.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|policy| serde_json::to_string(&policy).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(policy) => RCString::from_str(policy.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|policys| serde_json::to_string(&policys).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(policys) => RCString::from_str(policys.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|group| serde_json::to_string(&group).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(group) => RCString::from_str(group.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|group| serde_json::to_string(&group).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(group) => RCString::from_str(group.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|groups| serde_json::to_string(&groups).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(groups) => RCString::from_str(groups.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&group_policy_attachment).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(group_policy_attachment) => RCString::from_str(group_policy_attachment.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&group_policy_attachments).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(group_policy_attachments) => {
                    RCString::from_str(group_policy_attachments.as_str())
                }
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|role| serde_json::to_string(&role).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(role) => RCString::from_str(role.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|role| serde_json::to_string(&role).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(role) => RCString::from_str(role.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let role = role.to_string();
        let role: objectscale_client::iam::Role =
            serde_json::from_str(&role).expect("deserialize role");

        management_client.management_client.update_role(role)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|role| serde_json::to_string(&role).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(role) => RCString::from_str(role.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update role", err);
            RCString::null()
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
                    set_error(e.to_string().as_str(), err);
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
                result.and_then(|roles| serde_json::to_string(&roles).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(roles) => RCString::from_str(roles.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&role_policy_attachment).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(role_policy_attachment) => RCString::from_str(role_policy_attachment.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&role_policy_attachments).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(role_policy_attachments) => RCString::from_str(role_policy_attachments.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&entities_for_policy).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(entities_for_policy) => RCString::from_str(entities_for_policy.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&user_group_membership).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_group_membership) => RCString::from_str(user_group_membership.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&user_group_memberships).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_group_memberships) => RCString::from_str(user_group_memberships.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
                serde_json::to_string(&user_group_memberships).map_err(|e| anyhow!(e))
            });
            clear_error();
            match result {
                Ok(user_group_memberships) => RCString::from_str(user_group_memberships.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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

/// ObjectstoreClient manages ObjectScale resources on ObjectStore with the ObjectScale ObjectStore REST APIs.
pub struct ObjectstoreClient {
    objectstore_client: client::ObjectstoreClient,
}

/// Create an bucket.
///
/// bucket: Bucket to create.
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_create_bucket(
    objectstore_client: *mut ObjectstoreClient,
    bucket: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let bucket = bucket.to_string();
        let bucket: objectscale_client::bucket::Bucket =
            serde_json::from_str(&bucket).expect("deserialize bucket");

        objectstore_client.objectstore_client.create_bucket(bucket)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|bucket| serde_yaml::to_string(&bucket).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(bucket) => RCString::from_str(bucket.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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
pub unsafe extern "C" fn objectstore_client_get_bucket(
    objectstore_client: *mut ObjectstoreClient,
    name: RCString,
    namespace: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();
        let namespace = namespace.to_string();

        objectstore_client
            .objectstore_client
            .get_bucket(&name, &namespace)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|bucket| serde_yaml::to_string(&bucket).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(bucket) => RCString::from_str(bucket.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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

/// Deletes the specified bucket.
///
/// name: Bucket name to be deleted. Cannot be empty.
/// namespace: Namespace associated. Cannot be empty.
/// emptyBucket: If true, the contents of the bucket will be emptied as part of the delete, otherwise it will fail if the bucket is not empty.
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_delete_bucket(
    objectstore_client: *mut ObjectstoreClient,
    name: RCString,
    namespace: RCString,
    empty_bucket: bool,
    err: Option<&mut RCString>,
) {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();
        let namespace = namespace.to_string();

        objectstore_client
            .objectstore_client
            .delete_bucket(&name, &namespace, empty_bucket)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete bucket", err);
        }
    }
}

/// Update an bucket.
///
/// bucket: Bucket to update.
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_update_bucket(
    objectstore_client: *mut ObjectstoreClient,
    bucket: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let bucket = bucket.to_string();
        let bucket: objectscale_client::bucket::Bucket =
            serde_json::from_str(&bucket).expect("deserialize bucket");

        objectstore_client.objectstore_client.update_bucket(bucket)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|bucket| serde_yaml::to_string(&bucket).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(bucket) => RCString::from_str(bucket.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update bucket", err);
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
pub unsafe extern "C" fn objectstore_client_list_buckets(
    objectstore_client: *mut ObjectstoreClient,
    namespace: RCString,
    name_prefix: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let namespace = namespace.to_string();
        let name_prefix = name_prefix.to_string();

        objectstore_client
            .objectstore_client
            .list_buckets(&namespace, &name_prefix)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|buckets| serde_yaml::to_string(&buckets).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(buckets) => RCString::from_str(buckets.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
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

/// Creates the tenant which will associate an IAM Account within an objectstore.
///
/// tenant: Tenant to create
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_create_tenant(
    objectstore_client: *mut ObjectstoreClient,
    tenant: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let tenant = tenant.to_string();
        let tenant: objectscale_client::tenant::Tenant =
            serde_json::from_str(&tenant).expect("deserialize tenant");

        objectstore_client.objectstore_client.create_tenant(tenant)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|tenant| serde_yaml::to_string(&tenant).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(tenant) => RCString::from_str(tenant.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during create tenant", err);
            RCString::null()
        }
    }
}

/// Get the tenant.
///
/// name: The associated account id. Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_get_tenant(
    objectstore_client: *mut ObjectstoreClient,
    name: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();

        objectstore_client.objectstore_client.get_tenant(&name)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|tenant| serde_yaml::to_string(&tenant).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(tenant) => RCString::from_str(tenant.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during get tenant", err);
            RCString::null()
        }
    }
}

/// Updates Tenant details like default_bucket_size and alias.
///
/// tenant: Tenant to update
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_update_tenant(
    objectstore_client: *mut ObjectstoreClient,
    tenant: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let tenant = tenant.to_string();
        let tenant: objectscale_client::tenant::Tenant =
            serde_json::from_str(&tenant).expect("deserialize tenant");

        objectstore_client.objectstore_client.update_tenant(tenant)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|tenant| serde_yaml::to_string(&tenant).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(tenant) => RCString::from_str(tenant.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during update tenant", err);
            RCString::null()
        }
    }
}

/// Delete the tenant from an object store. Tenant must not own any buckets.
///
/// name: The associated account id. Cannot be empty.
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_delete_tenant(
    objectstore_client: *mut ObjectstoreClient,
    name: RCString,
    err: Option<&mut RCString>,
) {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name = name.to_string();

        objectstore_client.objectstore_client.delete_tenant(&name)
    })) {
        Ok(result) => {
            clear_error();
            match result {
                Ok(_) => return,
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                }
            }
        }
        Err(_) => {
            set_error("caught panic during delete tenant", err);
        }
    }
}

/// Get the list of tenants.
///
/// name_prefix: Case sensitive prefix of the tenant name with a wild card(*). Can be empty or any_prefix_string*.
///
#[no_mangle]
pub unsafe extern "C" fn objectstore_client_list_tenants(
    objectstore_client: *mut ObjectstoreClient,
    name_prefix: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let objectstore_client = &mut *objectstore_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let name_prefix = name_prefix.to_string();

        objectstore_client
            .objectstore_client
            .list_tenants(&name_prefix)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|tenants| serde_yaml::to_string(&tenants).map_err(|e| anyhow!(e)));
            clear_error();
            match result {
                Ok(tenants) => RCString::from_str(tenants.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during list tenants", err);
            RCString::null()
        }
    }
}
