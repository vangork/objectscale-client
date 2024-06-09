mod client;

use pyo3::prelude::*;
use client::{Client, PyAccount};

#[pymodule]
fn objectscale_client(m: &Bound<'_, PyModule>) -> PyResult<()>{
    m.add_class::<Client>()?;
    m.add_class::<PyAccount>()?;
    Ok(())
}
