mod client;
mod iam;

use client::ManagementClient;
use iam::{Account, Tag};
use pyo3::prelude::*;

#[pymodule]
fn objectscale_client(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ManagementClient>()?;
    m.add_class::<Account>()?;
    m.add_class::<Tag>()?;
    Ok(())
}
