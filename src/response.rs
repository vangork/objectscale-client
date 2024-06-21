use anyhow::{bail, Result};
use reqwest::blocking::Response;
use serde::de;

pub(crate) fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;

    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(de::Error::unknown_variant(s, &["true", "false"])),
    }
}

pub(crate) fn get_content_text(reponse: Response) -> Result<String> {
    let status = reponse.status();
    let text = reponse.text()?;
    if status.is_client_error() || status.is_server_error() {
        bail!("Request failed: {}", text);
    }
    Ok(text)
}
