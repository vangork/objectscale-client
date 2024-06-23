use crate::string::RCString;
use objectscale_client::iam::Account;
use std::convert::From;

// #[repr(C)]
// pub struct Tag {
//     pub key: String,
//     pub value: String,
// }

#[repr(C)]
pub struct CAccount {
    pub account_id: RCString,
    pub objscale: RCString,
    pub create_date: RCString,
    pub encryption_enabled: bool,
    pub account_disabled: bool,
    pub alias: RCString,
    pub description: RCString,
    pub protection_enabled: bool,
    pub tso_id: RCString,
    //pub tags: Vec<Tag>,
}

// CAccount is a copy from Account with ctypes
impl From<Account> for CAccount {
    fn from(account: Account) -> Self {
        Self {
            account_id: RCString::from_str(account.account_id.as_str()),
            objscale: RCString::from_str(account.objscale.as_str()),
            create_date: RCString::from_str(account.create_date.as_str()),
            encryption_enabled: account.encryption_enabled,
            account_disabled: account.account_disabled,
            alias: RCString::from_str(account.alias.as_str()),
            description: RCString::from_str(account.description.as_str()),
            protection_enabled: account.protection_enabled,
            tso_id: RCString::from_str(account.tso_id.as_str()),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_caccount(account: *mut CAccount) {
    if !account.is_null() {
        let account = Box::from_raw(account);
        account.account_id.to_vec();
        account.objscale.to_vec();
        account.create_date.to_vec();
        account.alias.to_vec();
        account.description.to_vec();
        account.tso_id.to_vec();
    }
}

pub fn new_account(caccount: &CAccount) -> Account {
    Account {
        account_id: caccount.account_id.to_string(),
        encryption_enabled: caccount.encryption_enabled,
        alias: caccount.alias.to_string(),
        description: caccount.description.to_string(),
        ..Default::default()
    }
}
