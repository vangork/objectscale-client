use crate::buffer::Buffer;
use crate::error::{clear_error, set_error};
use objectscale_client::api_client::{Account, APIClient};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

pub struct Client {
    api_client: APIClient,
}

#[repr(C)]
pub struct IamAccount {
    pub account_id: *const c_char,
}

impl IamAccount {
    pub fn new(account: Account) -> Self {
        let account_id = CString::new(account.account_id).expect("cstring account_id");
        Self {
            account_id: account_id.into_raw(),
        }
    }
}

#[no_mangle]
pub unsafe extern fn free_string(ptr: *const c_char) {
    // Take the ownership back to rust and drop the owner
    let _ = CString::from_raw(ptr as *mut _);
}

#[no_mangle]
pub unsafe extern "C" fn client_new(
    endpoint: *const c_char,
    username: *const c_char,
    password: *const c_char,
    insecure: bool,
    err: Option<&mut Buffer>,
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

    match catch_unwind(|| {
        Client {
            api_client: APIClient::new(
                endpoint,
                username,
                password,
                insecure,
            )
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
pub extern "C" fn client_destroy(client: *mut Client) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn client_create_account(
    client: *mut Client,
    alias: *const c_char,
    err: Option<&mut Buffer>,
) -> *mut IamAccount {
    let alias = match CStr::from_ptr(alias).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("invalid alias", err);
            return ptr::null_mut();
        }
    };

    let client = &mut *client;
    match catch_unwind(AssertUnwindSafe(move || {
        client.api_client.create_account(alias)
    })) {
        Ok(result) => match result {
            Ok(account) => {
                let iam_account = IamAccount::new(account);
                Box::into_raw(Box::new(iam_account))
            },
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
pub extern "C" fn iam_account_destroy(account: *mut IamAccount) {
    if !account.is_null() {
        unsafe {
            drop(Box::from_raw(account));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn client_delete_account(
    client: *mut Client,
    account_id: *const c_char,
    err: Option<&mut Buffer>,
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
        client.api_client.delete_account(account_id)
    })) {
        Ok(result) => {
            if let Err(e) = result {
                set_error(e.to_string().as_str(), err);
            }
        },
        Err(_) => {
            set_error("caught panic during account deletion", err);
        }
    }
}
