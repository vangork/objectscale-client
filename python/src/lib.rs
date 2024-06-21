mod client;

use client::{Client, PyAccount};
use pyo3::prelude::*;

#[pymodule]
fn objectscale_client(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    m.add_class::<PyAccount>()?;
    Ok(())
}
