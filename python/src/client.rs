use crate::iam::Account;
use objectscale_client::{client, iam};
use pyo3::prelude::*;
use pyo3::{exceptions, PyResult};

#[pyclass]
pub(crate) struct ManagementClient {
    management_client: client::ManagementClient,
}


#[pymethods]
impl ManagementClient {
    #[new]
    #[pyo3(text_signature = "(endpoint, username, password, insecure)")]
    fn new(endpoint: &str, username: &str, password: &str, insecure: bool) -> Self {
        let management_client = client::ManagementClient::new(endpoint, username, password, insecure);
        Self { management_client }
    }

    ///
    /// Create a Account.
    ///
    pub fn create_account(&mut self, account: &Account) -> PyResult<Account> {
        let account = iam::Account::from(account);
        let result = self.management_client.create_account(account);

        match result {
            Ok(account) => Ok(Account::from(account)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    ///
    /// Get a Account.
    ///
    pub fn get_account(&mut self, account_id: &str) -> PyResult<Account> {
        let result = self.management_client.get_account(account_id);

        match result {
            Ok(account) => Ok(Account::from(account)),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    ///
    /// Delete a Account.
    ///
    pub fn delete_account(&mut self, account_id: &str) -> PyResult<()> {
        let result = self.management_client.delete_account(account_id);

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }

    ///
    /// List all Accounts.
    ///
    pub fn list_accounts(&mut self) -> PyResult<Vec<Account>> {
        let result = self.management_client.list_accounts();

        match result {
            Ok(account) => Ok(account.into_iter().map(Account::from).collect()),
            Err(e) => Err(exceptions::PyValueError::new_err(format!("{:?}", e))),
        }
    }
}
