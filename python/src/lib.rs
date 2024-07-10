mod client;
mod iam;

use client::ManagementClient;
use iam::{Account, Tag};
use pyo3::prelude::*;

#[pymodule]
fn objectscale_client(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ManagementClient>()?;
    
    let iam = PyModule::new_bound(py, "iam")?;
    iam.add_class::<Account>()?;
    iam.add_class::<Tag>()?;
    m.add_submodule(&iam)?;
    
    Ok(())
}
