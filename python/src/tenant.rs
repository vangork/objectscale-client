use objectscale_client::tenant;
use pyo3::prelude::*;
use std::convert::From;

// A tenant is a logical construct resulting from the binding of an account to an object store.
#[derive(Clone, Debug, Default)]
#[pyclass(get_all)]
pub(crate) struct Tenant {
    // Name assigned to this resource in ECS. The resource name is set by a user and can be changed at any time. It is not a unique identifier.
    name: String,
    // Identifier that is generated by ECS when the resource is created. The resource Id is guaranteed to be unique and immutable across all virtual data centers for all time.
    #[pyo3(set)]
    id: String,
    // Hyperlink to the details for this resource
    link: String,
    // Timestamp that shows when this resource was created in ECS
    creation_time: String,
    // Indicates whether the resource is inactive. When a user removes a resource, the resource is put in this state before it is removed from the ECS database.
    inactive: bool,
    // Indicates whether the resource is global.
    global: bool,
    // Indicates whether the resource is remote.
    remote: bool,
    // Indicated whether the resource is an internal resource
    internal: bool,
    //
    tenant_default_vpool: String,
    // tag to enable encryption for the tenant
    #[pyo3(set)]
    is_encryption_enabled: bool,
    // Default bucket quota size.
    #[pyo3(set)]
    default_bucket_block_size: i64,
    // Tag to enable compliance compliance
    #[pyo3(set)]
    is_compliance_enabled: bool,
    //
    hard_quota_in_g_b: i64,
    //
    soft_quota_in_g_b: i64,
    //
    hard_quota_in_count: i64,
    //
    soft_quota_in_count: i64,
    // Alias of tenant
    #[pyo3(set)]
    alias: String,
}

impl From<tenant::Tenant> for Tenant {
    fn from(tenant: tenant::Tenant) -> Self {
        Self {
            name: tenant.name,
            id: tenant.id,
            link: tenant.link,
            creation_time: tenant.creation_time,
            inactive: tenant.inactive,
            global: tenant.global,
            remote: tenant.remote,
            internal: tenant.internal,
            tenant_default_vpool: tenant.tenant_default_vpool,
            is_encryption_enabled: tenant.is_encryption_enabled,
            default_bucket_block_size: tenant.default_bucket_block_size,
            is_compliance_enabled: tenant.is_compliance_enabled,
            hard_quota_in_g_b: tenant.hard_quota_in_g_b,
            soft_quota_in_g_b: tenant.soft_quota_in_g_b,
            hard_quota_in_count: tenant.hard_quota_in_count,
            soft_quota_in_count: tenant.soft_quota_in_count,
            alias: tenant.alias,
        }
    }
}

impl From<Tenant> for tenant::Tenant {
    fn from(tenant: Tenant) -> Self {
        Self {
            name: tenant.name,
            id: tenant.id,
            link: tenant.link,
            creation_time: tenant.creation_time,
            inactive: tenant.inactive,
            global: tenant.global,
            remote: tenant.remote,
            internal: tenant.internal,
            tenant_default_vpool: tenant.tenant_default_vpool,
            is_encryption_enabled: tenant.is_encryption_enabled,
            default_bucket_block_size: tenant.default_bucket_block_size,
            is_compliance_enabled: tenant.is_compliance_enabled,
            hard_quota_in_g_b: tenant.hard_quota_in_g_b,
            soft_quota_in_g_b: tenant.soft_quota_in_g_b,
            hard_quota_in_count: tenant.hard_quota_in_count,
            soft_quota_in_count: tenant.soft_quota_in_count,
            alias: tenant.alias,
        }
    }
}

#[pymethods]
impl Tenant {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __str__(&self) -> String {
        format!("{:?}", self)
    }
}
