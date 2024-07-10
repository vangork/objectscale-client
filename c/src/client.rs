use crate::error::{clear_error, set_error};
use crate::ffi::RCString;
use anyhow::anyhow;
use objectscale_client::client;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

pub struct ManagementClient {
    management_client: client::ManagementClient,
}

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
        ManagementClient {
            management_client: client::ManagementClient::new(&endpoint, &username, &password, insecure),
        }
    }) {
        Ok(client) => {
            clear_error();
            Box::into_raw(Box::new(client))
        }
        Err(_) => {
            set_error("caught panic during client creation", err);
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
pub unsafe extern "C" fn management_client_create_account(
    management_client: *mut ManagementClient,
    caccount: RCString,
    err: Option<&mut RCString>,
) -> RCString {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account = caccount.to_string();
        let account: objectscale_client::iam::Account =
            serde_json::from_str(&account).expect("deserialize account");
            management_client.management_client.create_account(account)
    })) {
        Ok(result) => {
            let result =
                result.and_then(|account| serde_json::to_string(&account).map_err(|e| anyhow!(e)));
            match result {
                Ok(account) => RCString::from_str(account.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during account creation", err);
            RCString::null()
        }
    }
}

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
            match result {
                Ok(account) => RCString::from_str(account.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during account get", err);
            RCString::null()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn management_client_delete_account(
    management_client: *mut ManagementClient,
    account_id: RCString,
    err: Option<&mut RCString>,
) {
    let management_client = &mut *management_client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_id = account_id.to_string();
        management_client.management_client.delete_account(&account_id)
    })) {
        Ok(result) => {
            if let Err(e) = result {
                set_error(e.to_string().as_str(), err);
            }
        }
        Err(_) => {
            set_error("caught panic during account deletion", err);
        }
    }
}

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
            match result {
                Ok(account) => RCString::from_str(account.as_str()),
                Err(e) => {
                    set_error(e.to_string().as_str(), err);
                    RCString::null()
                }
            }
        }
        Err(_) => {
            set_error("caught panic during account list", err);
            RCString::null()
        }
    }
}
