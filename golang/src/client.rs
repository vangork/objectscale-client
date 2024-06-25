use crate::error::{clear_error, set_error};
use crate::iam::{from_caccount, CAccount};
use crate::ffi::{RCArray, RCString};
use objectscale_client::client::ManagementClient;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

pub struct Client {
    management_client: ManagementClient,
}

#[no_mangle]
pub unsafe extern "C" fn new_client(
    endpoint: RCString,
    username: RCString,
    password: RCString,
    insecure: bool,
    err: Option<&mut RCString>,
) -> *mut Client {
    match catch_unwind(|| {
        let endpoint = endpoint.to_string();
        let username = username.to_string();
        let password = password.to_string();
        Client {
            management_client: ManagementClient::new(&endpoint, &username, &password, insecure),
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
        let account = from_caccount(caccount);
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
        }
        Err(_) => {
            set_error("caught panic during account creation", err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn client_get_account(
    client: *mut Client,
    account_id: RCString,
    err: Option<&mut RCString>,
) -> *mut CAccount {
    let client = &mut *client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_id = account_id.to_string();
        client.management_client.get_account(&account_id)
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
        }
        Err(_) => {
            set_error("caught panic during account get", err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn client_delete_account(
    client: *mut Client,
    account_id: RCString,
    err: Option<&mut RCString>,
) {
    let client = &mut *client;
    match catch_unwind(AssertUnwindSafe(move || {
        let account_id = account_id.to_string();
        client.management_client.delete_account(&account_id)
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
pub unsafe extern "C" fn client_list_accounts(
    client: *mut Client,
    err: Option<&mut RCString>,
) -> RCArray<CAccount> {
    let client = &mut *client;
    match catch_unwind(AssertUnwindSafe(move || {
        client.management_client.list_accounts()
    })) {
        Ok(result) => match result {
            Ok(accounts) => {
                RCArray::from_vec(accounts.into_iter().map(CAccount::from).collect())
            }
            Err(e) => {
                set_error(e.to_string().as_str(), err);
                RCArray::null()
            }
        }
        Err(_) => {
            set_error("caught panic during account list", err);
            RCArray::null()
        }
    }
}
