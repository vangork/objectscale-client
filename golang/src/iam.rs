use crate::string::{RCArray, RCString};
use objectscale_client::iam::{Account, Tag};
use std::convert::From;

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
    pub tags: RCArray<CTag>,
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
            tags: RCArray::from_vec(account.tags.into_iter().map(CTag::from).collect()),
        }
    }
}

pub fn from_caccount(caccount: &CAccount) -> Account {
    Account {
        account_id: caccount.account_id.to_string(),
        encryption_enabled: caccount.encryption_enabled,
        alias: caccount.alias.to_string(),
        description: caccount.description.to_string(),
        tags: caccount.tags.copy_to_vec().iter().map(from_ctag).collect(),
        ..Default::default()
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_caccount(caccount: *mut CAccount) {
    if !caccount.is_null() {
        let _ = Box::from_raw(caccount);
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct CTag {
    pub key: RCString,
    pub value: RCString,
}

impl From<Tag> for CTag {
    fn from(tag: Tag) -> Self {
        Self {
            key: RCString::from_str(tag.key.as_str()),
            value: RCString::from_str(tag.value.as_str()),
        }
    }
}

pub fn from_ctag(ctag: &CTag) -> Tag {
    Tag {
        key: ctag.key.to_string(),
        value: ctag.value.to_string(),
    }
}
#[no_mangle]
pub unsafe extern "C" fn destroy_ctag(ctag: *mut CTag) {
    if !ctag.is_null() {
        let _ = Box::from_raw(ctag);
    }
}

#[no_mangle]
pub extern "C" fn free_rcarray_ctag(rcarray: RCArray<CTag>) {
    let _ = rcarray.to_vec();
}
