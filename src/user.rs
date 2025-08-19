//! Define the user details.
//!
use crate::client::{ManagementClient, AUTH_HEADER_KEY};
use crate::response::get_content_text;
use anyhow::{bail, Context as _, Result};
use derive_builder::Builder;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_default_from_null;

/// ECS supports access by multiple tenants, where each tenant is defined by a namespace.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize)]
#[builder(setter(skip))]
#[serde(rename(serialize = "mgmt_user_info_create"))]
pub struct ManagementUser {
    /// User Id
    #[serde(rename = "userId")]
    #[builder(setter(into, skip = false))]
    pub user_id: String,
    /// User Password. Updatable
    #[serde(default)]
    #[builder(setter(into, skip = false))]
    pub password: String,
    /// Flag indicating whether management user is System Admin. Updatable
    #[serde(rename = "isSystemAdmin")]
    #[builder(setter(skip = false), default = "false")]
    pub is_system_admin: bool,
    /// Flag indicating whether management user is System Monitor. Updatable
    #[serde(rename = "isSystemMonitor")]
    #[builder(setter(skip = false), default = "false")]
    pub is_system_monitor: bool,
    /// Flag indicating whether management user is Security Admin. Updatable
    #[serde(rename = "isSecurityAdmin")]
    #[builder(setter(skip = false), default = "false")]
    pub is_security_admin: bool,
    /// If set to true, its a domain.
    pub is_external_group: bool,
    /// If set to true, the user is locked. Updatable, but can only set from `true` to `false`
    pub is_locked: bool,
    /// Value of last time password changed
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub last_time_password_changed: String,
}

#[derive(Debug, Deserialize)]
struct ListManagementUsersResponse {
    pub mgmt_user_info: Vec<ManagementUser>,
}

impl ManagementUser {
    pub(crate) fn create(client: &mut ManagementClient, user: &Self) -> Result<Self> {
        let request_url = format!("{}vdc/users", client.endpoint);
        let body = quick_xml::se::to_string(&user)?;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header(CONTENT_TYPE, "application/xml")
            .body(body)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to create management user")?;
        let resp: Self = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ManagementUser from creation response payload. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp)
    }

    pub(crate) fn get(client: &mut ManagementClient, id: &str) -> Result<Self> {
        let request_url = format!("{}vdc/users/{}", client.endpoint, id);
        let resp = client
            .http_client
            .get(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get management user")?;
        let resp: Self = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise management user. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp)
    }

    pub(crate) fn update_user(
        client: &mut ManagementClient,
        id: &str,
        password: &str,
        is_system_admin: bool,
        is_system_monitor: bool,
        is_security_admin: bool,
    ) -> Result<()> {
        let request_url = format!("{}vdc/users/{}", client.endpoint, id);
        let body = format!(
            r#"{{"password":"{}","isSystemAdmin":{},"isSystemMonitor":{},"isSecurityAdmin":{}}}"#,
            password, is_system_admin, is_system_monitor, is_security_admin
        );
        let resp = client
            .http_client
            .put(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Update management user failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn unlock(client: &mut ManagementClient, id: &str, password: &str) -> Result<()> {
        let request_url = format!("{}vdc/users/{}/unlock", client.endpoint, id);
        let body = format!(r#"{{"password":{}}}"#, password);
        let resp = client
            .http_client
            .put(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Unlock management user failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn update(client: &mut ManagementClient, user: Self) -> Result<Self> {
        let current_user = Self::get(client, &user.user_id)?;

        let password = user.password.trim().to_string();
        if user.is_system_admin != current_user.is_system_admin
            || user.is_system_monitor != current_user.is_system_monitor
            || user.is_security_admin != current_user.is_security_admin
            || !password.is_empty()
        {
            Self::update_user(
                client,
                &user.user_id,
                &password,
                user.is_system_admin,
                user.is_system_monitor,
                user.is_security_admin,
            )?;
        }

        if !user.is_locked && current_user.is_locked {
            Self::unlock(client, &user.user_id, &password)?;
        }

        Self::get(client, &user.user_id)
    }

    pub(crate) fn delete(client: &mut ManagementClient, id: &str) -> Result<()> {
        let request_url = format!("{}vdc/users/{}/deactivate", client.endpoint, id);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .send()?;
        if !resp.status().is_success() {
            bail!("Delete management user failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient) -> Result<Vec<Self>> {
        let request_url = format!("{}vdc/users", client.endpoint);
        let resp = client
            .http_client
            .get(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .send()?;

        let text = get_content_text(resp).with_context(|| "Failed to list management users")?;
        let resp: ListManagementUsersResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListManagementUsersResponse. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp.mgmt_user_info)
    }
}
