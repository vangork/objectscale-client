//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

//! Define the user details.
//!
use crate::client::{ManagementClient, AUTH_HEADER_KEY};
use crate::response::get_content_text;
use anyhow::{bail, Context as _, Result};
use derive_builder::Builder;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_default_from_null;

/// Management users can be assigned to VDC-wide management roles and are not associated with a namespace
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[builder(setter(skip))]
#[serde(rename(serialize = "mgmt_user_info_create"))]
pub struct ManagementUser {
    /// User Id. Required
    #[serde(rename = "userId")]
    #[builder(setter(into, skip = false))]
    pub user_id: String,
    /// User Password. Required. Updatable
    #[serde(default)]
    #[builder(setter(into, skip = false))]
    pub password: String,
    /// Flag indicating whether management user is System Admin. Default: false. Updatable
    #[serde(rename = "isSystemAdmin")]
    #[builder(setter(skip = false), default = "false")]
    pub is_system_admin: bool,
    /// Flag indicating whether management user is System Monitor. Default: false. Updatable
    #[serde(rename = "isSystemMonitor")]
    #[builder(setter(skip = false), default = "false")]
    pub is_system_monitor: bool,
    /// Flag indicating whether management user is Security Admin. Default: false. Updatable
    #[serde(rename = "isSecurityAdmin")]
    #[builder(setter(skip = false), default = "false")]
    pub is_security_admin: bool,
    /// If set to true, its a domain.
    pub is_external_group: bool,
    /// If set to true, the user is locked. No need to set value during creation, by default is false. Updatable, but can only set from `true` to `false`
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
                "Unable to deserialise ManagementUser. Body was: \"{}\"",
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

    pub(crate) fn update(client: &mut ManagementClient, user: Self) -> Result<bool> {
        let current_user = Self::get(client, &user.user_id)?;
        let mut updated = false;

        let password = user.password.trim().to_string();
        if user.is_system_admin != current_user.is_system_admin
            || user.is_system_monitor != current_user.is_system_monitor
            || user.is_security_admin != current_user.is_security_admin
            || !password.is_empty()
        {
            updated = true;
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
            updated = true;
            Self::unlock(client, &user.user_id, &password)?;
        }

        Ok(updated)
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

/// Lables for Object User.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserTag {
    /// The name of a tag.
    pub name: String,
    /// The value of a tag.
    pub value: String,
}

/// Managing Swift passwords and assigning Swift users to groups.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct SwiftGroup {
    /// Password for the user. Empty for no password and group. Default: "". Updatable
    #[serde(default)]
    pub password: String,
    /// List of ADMIN groups for the user. Empty for no password and group. Default: []. Updatable
    pub groups_list: Vec<String>,
    /// Swift password configured.
    pub swift_password_configured: bool,
}

/// User can access the object store with a secret key.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct SecretKey {
    /// Secret key associated with this user.
    pub secret_key: String,
    /// Expiry time in minutes for the secret key. Empty for no expiry. Default: "".
    #[serde(default)]
    pub existing_key_expiry_time_mins: String,
    /// Secret key creation timestamp in ISO-8601 format
    pub key_timestamp: String,
    /// Secret key expiry timestamp in ISO-8601 format
    pub key_expiry_timestamp: String,
    /// SHA-256 hash of Secret key
    pub secret_key_id: String,
}

/// Object users can be assigned to management and object user roles for the namespace.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[builder(setter(skip))]
#[serde(rename(serialize = "user_create_param"))]
pub struct ObjectUser {
    /// User name. Required
    #[serde(rename(serialize = "user"))]
    #[builder(setter(into, skip = false))]
    pub name: String,
    /// Namespace that owns the user. Required
    #[builder(setter(into, skip = false))]
    pub namespace: String,
    /// Set true if user needs to be is to be locked, false otherwise. Default: false. Updatable
    #[builder(setter(skip = false), default = "false")]
    pub locked: bool,
    /// Gets the user's creation date as an ISO-8601 timestamp.
    pub created: String,
    /// The tags associated with this user. Default: []. Updatable
    #[builder(setter(skip = false), default)]
    pub tag: Vec<UserTag>,
    /// Gets the user's centerapassword.
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub centerapassword: String,
    /// Gets the user's swiftpassword.
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub swiftpassword: String,
    /// Managing Swift passwords and assigning Swift users to groups. Default: see SwiftGroup. Updatable
    #[builder(setter(skip = false), default)]
    #[serde(default)]
    pub swift_group: SwiftGroup,
    /// User can access the object store with a secret key. At most two secret keys can be created. Default: []. Updatable
    #[builder(setter(skip = false), default)]
    #[serde(default)]
    pub secret_keys: Vec<SecretKey>,
}

#[derive(Debug, Deserialize)]
struct BlobUser {
    pub userid: String,
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListObjectUsersResponse {
    #[serde(rename = "blobuser")]
    pub users: Vec<BlobUser>,
    pub max_users: Option<u64>,
    pub next_marker: Option<String>,
    pub filter: String,
    pub next_page_link: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct TagRequest {
    pub tags: Vec<UserTag>,
}

impl ObjectUser {
    pub(crate) fn create(client: &mut ManagementClient, user: &Self) -> Result<()> {
        let request_url = format!("{}object/users", client.endpoint);
        let body = quick_xml::se::to_string(&user)?;
        //let body = serde_json::to_string(&user)?;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .header(CONTENT_TYPE, "application/xml")
            .body(body)
            .send()?;
        get_content_text(resp).with_context(|| "Failed to create object user")?;
        Ok(())
    }

    pub(crate) fn get(client: &mut ManagementClient, name: &str, namespace: &str) -> Result<Self> {
        let request_url = format!(
            "{}object/users/{}/info?namespace={}",
            client.endpoint, name, namespace
        );
        let resp = client
            .http_client
            .get(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get object user")?;
        let mut resp: Self = serde_json::from_str(&text)
            .with_context(|| format!("Unable to deserialise ObjectUser. Body was: \"{}\"", text))?;

        let secret_keys = SecretKey::get(client, name, namespace)?;
        resp.secret_keys = secret_keys;
        let swift_group = SwiftGroup::get(client, name, namespace)?;
        resp.swift_group = swift_group;
        Ok(resp)
    }

    pub(crate) fn add_tag(
        client: &mut ManagementClient,
        name: &str,
        namespace: &str,
        tags: Vec<UserTag>,
    ) -> Result<()> {
        let tag_request = TagRequest { tags };
        let body = serde_json::to_string(&tag_request)?;
        let request_url = format!(
            "{}object/users/{}/tags?namespace={}",
            client.endpoint, name, namespace
        );
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Request failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn delete_tag(
        client: &mut ManagementClient,
        name: &str,
        namespace: &str,
        tags: Vec<UserTag>,
    ) -> Result<()> {
        let tag_request = TagRequest { tags };
        let body = serde_json::to_string(&tag_request)?;
        let request_url = format!(
            "{}object/users/{}/tags?namespace={}",
            client.endpoint, name, namespace
        );
        let resp = client
            .http_client
            .delete(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Request failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn update_lock(
        client: &mut ManagementClient,
        name: &str,
        namespace: &str,
        is_locked: bool,
    ) -> Result<()> {
        let body = format!(
            r#"{{"user":"{}","namespace":"{}","isLocked":{}}}"#,
            name, namespace, is_locked
        );
        let request_url = format!("{}object/users/lock", client.endpoint);
        let resp = client
            .http_client
            .put(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Update lock failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn update(client: &mut ManagementClient, user: &Self) -> Result<bool> {
        let current_user = Self::get(client, &user.name, &user.namespace)?;
        let mut updated = false;

        if user.locked != current_user.locked {
            updated = true;
            Self::update_lock(client, &user.name, &user.namespace, user.locked)?;
        }

        if user.tag != current_user.tag {
            updated = true;
            if !current_user.tag.is_empty() {
                Self::delete_tag(client, &user.name, &user.namespace, current_user.tag)?;
            }
            if !user.tag.is_empty() {
                Self::add_tag(client, &user.name, &user.namespace, user.tag.clone())?;
            }
        }

        if user.secret_keys != current_user.secret_keys {
            updated = true;
            for current_key in current_user.secret_keys.iter() {
                // TODO: verify the logic
                if !user.secret_keys.contains(current_key) {
                    SecretKey::delete(client, &user.name, &user.namespace, current_key)?;
                }
            }

            for key in user.secret_keys.iter() {
                // TODO: verify the logic
                if !current_user.secret_keys.contains(key) {
                    SecretKey::create(client, &user.name, &user.namespace, key)?;
                }
            }
        }

        if !current_user.swift_group.swift_password_configured {
            if !user.swift_group.password.is_empty() && !user.swift_group.groups_list.is_empty() {
                updated = true;
                SwiftGroup::create(client, &user.name, &user.namespace, &user.swift_group)?;
            }
        } else if user.swift_group.password.is_empty() || user.swift_group.groups_list.is_empty() {
            updated = true;
            SwiftGroup::delete(client, &user.name, &user.namespace)?;
        } else {
            // TODO: to verify if password changes
            updated = true;
            SwiftGroup::update(client, &user.name, &user.namespace, &user.swift_group)?;
        }

        Ok(updated)
    }

    pub(crate) fn delete(client: &mut ManagementClient, name: &str, namespace: &str) -> Result<()> {
        let request_url = format!("{}object/users/deactivate", client.endpoint);
        let body = format!(r#"{{"user":"{}","namespace":"{}"}}"#, name, namespace);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Delete object user failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn list(client: &mut ManagementClient) -> Result<Vec<Self>> {
        let request_url = format!("{}object/users", client.endpoint);
        let resp = client
            .http_client
            .get(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to list object users")?;
        // sample:
        // {"blobuser":[{"userid":"object_admin1","namespace":"ns1"},{"userid":"object_user1","namespace":"ns1"}],
        // "MaxUsers":null,"NextMarker":null,"Filter":"userid=*","NextPageLink":null}
        let mut resp: ListObjectUsersResponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise ListObjectUsersResponse. Body was: \"{}\"",
                text
            )
        })?;
        let mut users: Vec<Self> = vec![];
        for blob_user in resp.users {
            let user = Self::get(client, &blob_user.userid, &blob_user.namespace)
                .with_context(|| "Failed to list object users")?;
            users.push(user);
        }
        while let Some(marker) = resp.next_marker {
            let request_url = format!("{}object/users?marker={}", client.endpoint, marker);
            let response = client
                .http_client
                .get(request_url)
                .header(ACCEPT, "application/json")
                .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
                .send()?;
            let text = get_content_text(response).with_context(|| "Failed to list object users")?;
            resp = serde_json::from_str(&text).with_context(|| {
                format!(
                    "Unable to deserialise ListObjectUsersResponse. Body was: \"{}\"",
                    text
                )
            })?;
            for blob_user in resp.users {
                let user = Self::get(client, &blob_user.userid, &blob_user.namespace)
                    .with_context(|| "Failed to list object users")?;
                users.push(user);
            }
        }
        Ok(users)
    }
}

#[derive(Debug, Deserialize)]
struct SecretKeyReponse {
    pub secret_key_1: String,
    pub secret_key_1_exist: bool,
    pub key_timestamp_1: String,
    pub key_expiry_timestamp_1: String,
    pub secret_key_2: String,
    pub secret_key_2_exist: bool,
    pub key_timestamp_2: String,
    pub key_expiry_timestamp_2: String,
    pub secret_key_1_id: Option<String>,
    pub secret_key_2_id: Option<String>,
}

impl SecretKey {
    pub(crate) fn create(
        client: &mut ManagementClient,
        user: &str,
        namespace: &str,
        secret_key: &Self,
    ) -> Result<Self> {
        let request_url = format!("{}object/user-secret-keys/{}", client.endpoint, user);
        let expiry = if secret_key.existing_key_expiry_time_mins.is_empty() {
            "".to_string()
        } else {
            format!(
                r#","existing_key_expiry_time_mins":"{}""#,
                secret_key.existing_key_expiry_time_mins
            )
        };
        let body = format!(r#"{{"namespace":"{}"{}}}"#, namespace, expiry);
        let resp = client
            .http_client
            .post(&request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to create secret key")?;
        let resp: Self = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise SecretKey from get response. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp)
    }

    pub(crate) fn get(
        client: &mut ManagementClient,
        user: &str,
        namespace: &str,
    ) -> Result<Vec<Self>> {
        let request_url = format!(
            "{}object/user-secret-keys/{}/{}",
            client.endpoint, user, namespace
        );
        let resp = client
            .http_client
            .get(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .send()?;
        let text = get_content_text(resp).with_context(|| "Failed to get secret key")?;
        let resp: SecretKeyReponse = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise SecretKeyReponse from get response. Body was: \"{}\"",
                text
            )
        })?;
        let mut secret_keys = Vec::new();
        if let Some(id) = resp.secret_key_1_id {
            let secret_key = SecretKey {
                secret_key: resp.secret_key_1,
                key_timestamp: resp.key_timestamp_1,
                key_expiry_timestamp: resp.key_expiry_timestamp_1,
                existing_key_expiry_time_mins: "".to_string(),
                secret_key_id: id,
            };
            secret_keys.push(secret_key);
        }
        if let Some(id) = resp.secret_key_2_id {
            let secret_key = SecretKey {
                secret_key: resp.secret_key_2,
                key_timestamp: resp.key_timestamp_2,
                key_expiry_timestamp: resp.key_expiry_timestamp_2,
                existing_key_expiry_time_mins: "".to_string(),
                secret_key_id: id,
            };
            secret_keys.push(secret_key);
        }
        Ok(secret_keys)
    }

    pub(crate) fn delete(
        client: &mut ManagementClient,
        user: &str,
        namespace: &str,
        secret_key: &Self,
    ) -> Result<()> {
        let request_url = format!(
            "{}object/user-secret-keys/{}/deactivate",
            client.endpoint, user
        );
        let body = format!(
            r#"{{"namespace":"{}","secret_key":"{}","secret_key_id":"{}"}}"#,
            namespace, secret_key.secret_key, secret_key.secret_key_id
        );
        let resp = client
            .http_client
            .post(&request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Delete secret key failed: {}", resp.text()?);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct SwiftGroupRequest {
    pub password: String,
    pub groups_list: Vec<String>,
    pub namespace: String,
}

impl SwiftGroup {
    pub(crate) fn create(
        client: &mut ManagementClient,
        user: &str,
        namespace: &str,
        swift_group: &Self,
    ) -> Result<()> {
        let request_url = format!("{}object/user-password/{}", client.endpoint, user);
        let body = serde_json::to_string(&SwiftGroupRequest {
            password: swift_group.password.clone(),
            groups_list: swift_group.groups_list.clone(),
            namespace: namespace.to_string(),
        })?;
        let resp = client
            .http_client
            .put(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Create swift group failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn get(client: &mut ManagementClient, user: &str, namespace: &str) -> Result<Self> {
        let request_url = format!(
            "{}object/user-password/{}/{}",
            client.endpoint, user, namespace
        );
        let resp = client
            .http_client
            .get(request_url)
            .header(ACCEPT, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .send()?;
        let status = resp.status();
        let text = resp.text()?;
        if status.is_client_error() || status.is_server_error() {
            if text.contains("Unable to find entity specified in URL with the given id") {
                return Ok(Self::default());
            } else {
                bail!("Failed to get swift group: {}", text);
            }
        };
        let resp: Self = serde_json::from_str(&text).with_context(|| {
            format!(
                "Unable to deserialise SwiftGroup from get response. Body was: \"{}\"",
                text
            )
        })?;
        Ok(resp)
    }

    pub(crate) fn update(
        client: &mut ManagementClient,
        user: &str,
        namespace: &str,
        swift_group: &Self,
    ) -> Result<()> {
        let request_url = format!("{}object/user-password/{}", client.endpoint, user);
        let body = serde_json::to_string(&SwiftGroupRequest {
            password: swift_group.password.clone(),
            groups_list: swift_group.groups_list.clone(),
            namespace: namespace.to_string(),
        })?;
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Create swift group failed: {}", resp.text()?);
        }
        Ok(())
    }

    pub(crate) fn delete(client: &mut ManagementClient, user: &str, namespace: &str) -> Result<()> {
        let request_url = format!(
            "{}object/user-password/{}/deactivate",
            client.endpoint, user
        );
        let body = format!(r#"{{"namespace":"{}"}}"#, namespace);
        let resp = client
            .http_client
            .post(request_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTH_HEADER_KEY, client.access_token.as_ref().unwrap())
            .body(body)
            .send()?;
        if !resp.status().is_success() {
            bail!("Remove swift group failed: {}", resp.text()?);
        }
        Ok(())
    }
}
