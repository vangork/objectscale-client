use objectscale_client::client::ManagementClient;
use objectscale_client::iam::{Account, AccountBuilder, Tag};
use pyo3::prelude::*;
use pyo3::{exceptions, PyResult};
use std::convert::From;

#[pyclass]
pub(crate) struct Client {
    management_client: ManagementClient,
}

#[derive(Clone)]
#[pyclass(get_all)]
pub(crate) struct PyTag {
    key: String,
    value: String,
}

impl From<Tag> for PyTag {
    fn from(tag: Tag) -> Self {
        Self {
            key: tag.key,
            value: tag.value,
        }
    }
}

#[pyclass(get_all)]
pub(crate) struct PyAccount {
    account_id: String,
    objscale: String,
    create_date: String,
    encryption_enabled: bool,
    account_disabled: bool,
    alias: String,
    description: String,
    protection_enabled: bool,
    tso_id: String,
    tags: Vec<PyTag>,
}

impl From<Account> for PyAccount {
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
            tags: account.tags.into_iter().map(PyTag::from).collect(),
        }
    }
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(text_signature = "(endpoint, username, password, insecure)")]
    fn new(endpoint: &str, username: &str, password: &str, insecure: bool) -> Self {
        let management_client = ManagementClient::new(endpoint, username, password, insecure);
        Self { management_client }
    }

    ///
    /// Create a Account.
    ///
    #[pyo3(text_signature = "($self, alias)")]
    pub fn create_account(&mut self, alias: &str) -> PyResult<PyAccount> {
        let account = AccountBuilder::default().alias(alias).build().unwrap();
        let result = self.management_client.create_account(account);

        match result {
            Ok(account) => Ok(PyAccount::from(account)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    ///
    /// Delete a Account.
    ///
    #[pyo3(text_signature = "($self, account_id)")]
    pub fn delete_account(&mut self, account_id: &str) -> PyResult<()> {
        let result = self.management_client.delete_account(account_id);

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }
}
