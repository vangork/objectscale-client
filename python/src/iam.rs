use objectscale_client::iam;
use pyo3::prelude::*;
use std::convert::From;

#[derive(Clone, Default)]
#[pyclass(get_all)]
pub(crate) struct Tag {
    #[pyo3(set)]
    key: String,
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

impl From<&Tag> for iam::Tag {
    fn from(tag: &Tag) -> Self {
        Self {
            key: tag.key.clone(),
            value: tag.value.clone(),
        }
    }
}

#[pymethods]
impl Tag {
    #[new]
    fn new() -> Self {
        Self::default()
    }
}


#[derive(Clone, Default)]
#[pyclass(get_all)]
pub(crate) struct Account {
    account_id: String,
    objscale: String,
    create_date: String,
    #[pyo3(set)]
    encryption_enabled: bool,
    account_disabled: bool,
    #[pyo3(set)]
    alias: String,
    #[pyo3(set)]
    description: String,
    protection_enabled: bool,
    tso_id: String,
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

impl From<&Account> for iam::Account {
    fn from(account: &Account) -> Self {
        Self {
            account_id: account.account_id.clone(),
            objscale: account.objscale.clone(),
            create_date: account.create_date.clone(),
            encryption_enabled: account.encryption_enabled,
            account_disabled: account.account_disabled,
            alias: account.alias.clone(),
            description: account.description.clone(),
            protection_enabled: account.protection_enabled,
            tso_id: account.tso_id.clone(),
            tags: account.tags.iter().map(iam::Tag::from).collect(),
        }
    }
}

#[pymethods]
impl Account {
    #[new]
    fn new() -> Self {
        Self::default()
    }
}
