//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

use objectscale_client::user;
use pyo3::prelude::*;
use serde::Serialize;
use std::convert::From;

// Management users can be assigned to VDC-wide management roles and are not associated with a namespace
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct ManagementUser {
    // User Id. Required
    #[pyo3(set)]
    user_id: String,
    // User Password. Required. Updatable
    #[pyo3(set)]
    password: String,
    // Flag indicating whether management user is System Admin. Default: false. Updatable
    #[pyo3(set)]
    is_system_admin: bool,
    // Flag indicating whether management user is System Monitor. Default: false. Updatable
    #[pyo3(set)]
    is_system_monitor: bool,
    // Flag indicating whether management user is Security Admin. Default: false. Updatable
    #[pyo3(set)]
    is_security_admin: bool,
    // If set to true, its a domain.
    is_external_group: bool,
    // If set to true, the user is locked. No need to set value during creation, by default is false. Updatable, but can only set from `true` to `false`
    is_locked: bool,
    // Value of last time password changed
    last_time_password_changed: String,
}

impl From<user::ManagementUser> for ManagementUser {
    fn from(management_user: user::ManagementUser) -> Self {
        Self {
            user_id: management_user.user_id,
            password: management_user.password,
            is_system_admin: management_user.is_system_admin,
            is_system_monitor: management_user.is_system_monitor,
            is_security_admin: management_user.is_security_admin,
            is_external_group: management_user.is_external_group,
            is_locked: management_user.is_locked,
            last_time_password_changed: management_user.last_time_password_changed,
        }
    }
}

impl From<ManagementUser> for user::ManagementUser {
    fn from(management_user: ManagementUser) -> Self {
        Self {
            user_id: management_user.user_id,
            password: management_user.password,
            is_system_admin: management_user.is_system_admin,
            is_system_monitor: management_user.is_system_monitor,
            is_security_admin: management_user.is_security_admin,
            is_external_group: management_user.is_external_group,
            is_locked: management_user.is_locked,
            last_time_password_changed: management_user.last_time_password_changed,
        }
    }
}

#[pymethods]
impl ManagementUser {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// Object users can be assigned to management and object user roles for the namespace.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct ObjectUser {
    // User name. Required
    #[pyo3(set)]
    name: String,
    // Namespace that owns the user. Required
    #[pyo3(set)]
    namespace: String,
    // Set true if user needs to be is to be locked, false otherwise. Default: false. Updatable
    #[pyo3(set)]
    locked: bool,
    // Gets the user's creation date as an ISO-8601 timestamp.
    created: String,
    // The tags associated with this user. Default: []. Updatable
    #[pyo3(set)]
    tag: Vec<UserTag>,
    // Gets the user's centerapassword.
    centerapassword: String,
    // Gets the user's swiftpassword.
    swiftpassword: String,
    // Managing Swift passwords and assigning Swift users to groups. Default: see SwiftGroup. Updatable
    #[pyo3(set)]
    swift_group: SwiftGroup,
    // User can access the object store with a secret key. At most two secret keys can be created. Default: []. Updatable
    #[pyo3(set)]
    secret_keys: Vec<SecretKey>,
}

impl From<user::ObjectUser> for ObjectUser {
    fn from(object_user: user::ObjectUser) -> Self {
        Self {
            name: object_user.name,
            namespace: object_user.namespace,
            locked: object_user.locked,
            created: object_user.created,
            tag: object_user.tag.into_iter().map(UserTag::from).collect(),
            centerapassword: object_user.centerapassword,
            swiftpassword: object_user.swiftpassword,
            swift_group: SwiftGroup::from(object_user.swift_group),
            secret_keys: object_user
                .secret_keys
                .into_iter()
                .map(SecretKey::from)
                .collect(),
        }
    }
}

impl From<ObjectUser> for user::ObjectUser {
    fn from(object_user: ObjectUser) -> Self {
        Self {
            name: object_user.name,
            namespace: object_user.namespace,
            locked: object_user.locked,
            created: object_user.created,
            tag: object_user
                .tag
                .into_iter()
                .map(user::UserTag::from)
                .collect(),
            centerapassword: object_user.centerapassword,
            swiftpassword: object_user.swiftpassword,
            swift_group: user::SwiftGroup::from(object_user.swift_group),
            secret_keys: object_user
                .secret_keys
                .into_iter()
                .map(user::SecretKey::from)
                .collect(),
        }
    }
}

#[pymethods]
impl ObjectUser {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// User can access the object store with a secret key.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct SecretKey {
    // Secret key associated with this user.
    #[pyo3(set)]
    secret_key: String,
    // Expiry time in minutes for the secret key. Empty for no expiry. Default: "".
    #[pyo3(set)]
    existing_key_expiry_time_mins: String,
    // Secret key creation timestamp in ISO-8601 format
    #[pyo3(set)]
    key_timestamp: String,
    // Secret key expiry timestamp in ISO-8601 format
    #[pyo3(set)]
    key_expiry_timestamp: String,
    // SHA-256 hash of Secret key
    #[pyo3(set)]
    secret_key_id: String,
}

impl From<user::SecretKey> for SecretKey {
    fn from(secret_key: user::SecretKey) -> Self {
        Self {
            secret_key: secret_key.secret_key,
            existing_key_expiry_time_mins: secret_key.existing_key_expiry_time_mins,
            key_timestamp: secret_key.key_timestamp,
            key_expiry_timestamp: secret_key.key_expiry_timestamp,
            secret_key_id: secret_key.secret_key_id,
        }
    }
}

impl From<SecretKey> for user::SecretKey {
    fn from(secret_key: SecretKey) -> Self {
        Self {
            secret_key: secret_key.secret_key,
            existing_key_expiry_time_mins: secret_key.existing_key_expiry_time_mins,
            key_timestamp: secret_key.key_timestamp,
            key_expiry_timestamp: secret_key.key_expiry_timestamp,
            secret_key_id: secret_key.secret_key_id,
        }
    }
}

#[pymethods]
impl SecretKey {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// Managing Swift passwords and assigning Swift users to groups.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct SwiftGroup {
    // Password for the user. Empty for no password and group. Default: "". Updatable
    #[pyo3(set)]
    password: String,
    // List of ADMIN groups for the user. Empty for no password and group. Default: []. Updatable
    #[pyo3(set)]
    groups_list: Vec<String>,
    // Swift password configured.
    #[pyo3(set)]
    swift_password_configured: bool,
}

impl From<user::SwiftGroup> for SwiftGroup {
    fn from(swift_group: user::SwiftGroup) -> Self {
        Self {
            password: swift_group.password,
            groups_list: swift_group.groups_list,
            swift_password_configured: swift_group.swift_password_configured,
        }
    }
}

impl From<SwiftGroup> for user::SwiftGroup {
    fn from(swift_group: SwiftGroup) -> Self {
        Self {
            password: swift_group.password,
            groups_list: swift_group.groups_list,
            swift_password_configured: swift_group.swift_password_configured,
        }
    }
}

#[pymethods]
impl SwiftGroup {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}

// Lables for Object User.
#[derive(Clone, Debug, Default, Serialize)]
#[pyclass(get_all)]
pub(crate) struct UserTag {
    // The name of a tag.
    #[pyo3(set)]
    name: String,
    // The value of a tag.
    #[pyo3(set)]
    value: String,
}

impl From<user::UserTag> for UserTag {
    fn from(user_tag: user::UserTag) -> Self {
        Self {
            name: user_tag.name,
            value: user_tag.value,
        }
    }
}

impl From<UserTag> for user::UserTag {
    fn from(user_tag: UserTag) -> Self {
        Self {
            name: user_tag.name,
            value: user_tag.value,
        }
    }
}

#[pymethods]
impl UserTag {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap())
    }
}
