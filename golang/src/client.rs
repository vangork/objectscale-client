use crate::error::{clear_error, set_error};
use crate::iam::{new_account, CAccount};
use crate::string::RCString;
use objectscale_client::client::ManagementClient;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

pub struct Client {
    management_client: ManagementClient,
}

#[no_mangle]
pub unsafe extern "C" fn new_client(
    endpoint: *const c_char,
    username: *const c_char,
    password: *const c_char,
    insecure: bool,
    err: Option<&mut RCString>,
) -> *mut Client {
    let endpoint = match CStr::from_ptr(endpoint).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("invalid endpoint", err);
            return ptr::null_mut();
        }
    };
    let username = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("invalid username", err);
            return ptr::null_mut();
        }
    };
    let password = match CStr::from_ptr(password).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("invalid password", err);
            return ptr::null_mut();
        }
    };

    match catch_unwind(|| Client {
        management_client: ManagementClient::new(endpoint, username, password, insecure),
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
pub extern "C" fn destroy_client(client: *mut Client) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn client_create_account(
    client: *mut Client,
    caccount: &CAccount,
    err: Option<&mut RCString>,
) -> *mut CAccount {
    let client = &mut *client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account = new_account(caccount);
        client.management_client.create_account(account)
    })) {
        Ok(result) => match result {
            Ok(account) => {
                let caccount = CAccount::from(account);
                Box::into_raw(Box::new(caccount))
            }
            Err(e) => {
                set_error(e.to_string().as_str(), err);
                ptr::null_mut()
            }
        },
        Err(_) => {
            set_error("caught panic during account creation", err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn client_delete_account(
    client: *mut Client,
    account_id: *const c_char,
    err: Option<&mut RCString>,
) {
    let account_id = match CStr::from_ptr(account_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("invalid account_id", err);
            return;
        }
    };
    let client = &mut *client;
    match catch_unwind(AssertUnwindSafe(move || {
        client.management_client.delete_account(account_id)
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
