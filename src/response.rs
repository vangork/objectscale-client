use anyhow::{bail, Result};
use reqwest::blocking::Response;

pub(crate) fn get_content_text(reponse: Response) -> Result<String> {
    let status = reponse.status();
    let text = reponse.text()?;
    if status.is_client_error() || status.is_server_error() {
        bail!("Request failed: {}", text);
    }
    Ok(text)
}
