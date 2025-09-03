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
