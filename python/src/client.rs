use objectscale_client::api_client::{Account, APIClient};
use pyo3::prelude::*;
use pyo3::{exceptions, PyResult};

#[pyclass]
pub(crate) struct Client {
    api_client: APIClient,
}

#[pyclass(get_all)]
pub(crate) struct IamAccount {
    account_id: String,
    objscale: String,
    create_date: String,
    encryption_enabled: bool,
    account_disabled: bool,
    alias: String,
    description: String,
    protection_enabled: bool,
    tso_id: String,
}

impl IamAccount {
    pub fn new(account: Account) -> Self {
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
        }
    }
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(text_signature = "(endpoint, username, password, insecure)")]
    fn new(
        endpoint: &str,
        username: &str,
        password: &str,
        insecure: bool,
    ) -> Self {
        let api_client = APIClient::new(endpoint, username, password, insecure);
        Self { api_client }
    }

    ///
    /// Create a Account.
    ///
    #[pyo3(text_signature = "($self, alias)")]
    pub fn create_account(&mut self, alias: &str) -> PyResult<IamAccount> {
        let result = self.api_client.create_account(alias);

        match result {
            Ok(account) => Ok(IamAccount::new(account)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    ///
    /// Delete a Account.
    ///
    #[pyo3(text_signature = "($self, account_id)")]
    pub fn delete_account(&mut self, account_id: &str) -> PyResult<()> {
        let result = self.api_client.delete_account(account_id);

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }
}
