mod client;
mod iam;
mod provisioning;
mod replication;
mod tenancy;
mod user;

use client::ManagementClient;
use iam::{
    AccessKey, EntitiesForPolicy, Group, GroupPolicyAttachment, IamTag, PermissionsBoundary,
    Policy, Role, RolePolicyAttachment, SamlProvider, User, UserGroupMembership,
    UserPolicyAttachment,
};
use provisioning::{
    Bucket, BucketTag, MetaData, MinMaxGovernor, ProvisioningLink, SearchMetaData, StoragePool,
    Vdc, VdcKeystore,
};
use replication::{ReplicationGroup, VarrayMapping};
use tenancy::{Attribute, Namespace, RetentionClass, RetentionClasses, TenancyLink, UserMapping};
use user::{ManagementUser, ObjectUser, UserTag};

use pyo3::prelude::*;

#[pymodule]
fn objectscale_client(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new(py, "client")?;
    module.add_class::<ManagementClient>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new(py, "iam")?;
    module.add_class::<AccessKey>()?;
    module.add_class::<EntitiesForPolicy>()?;
    module.add_class::<Group>()?;
    module.add_class::<GroupPolicyAttachment>()?;
    module.add_class::<IamTag>()?;
    module.add_class::<PermissionsBoundary>()?;
    module.add_class::<Policy>()?;
    module.add_class::<Role>()?;
    module.add_class::<RolePolicyAttachment>()?;
    module.add_class::<SamlProvider>()?;
    module.add_class::<User>()?;
    module.add_class::<UserGroupMembership>()?;
    module.add_class::<UserPolicyAttachment>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new(py, "provisioning")?;
    module.add_class::<Bucket>()?;
    module.add_class::<BucketTag>()?;
    module.add_class::<MetaData>()?;
    module.add_class::<MinMaxGovernor>()?;
    module.add_class::<ProvisioningLink>()?;
    module.add_class::<SearchMetaData>()?;
    module.add_class::<StoragePool>()?;
    module.add_class::<Vdc>()?;
    module.add_class::<VdcKeystore>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new(py, "replication")?;
    module.add_class::<ReplicationGroup>()?;
    module.add_class::<VarrayMapping>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new(py, "tenancy")?;
    module.add_class::<Attribute>()?;
    module.add_class::<Namespace>()?;
    module.add_class::<RetentionClass>()?;
    module.add_class::<RetentionClasses>()?;
    module.add_class::<TenancyLink>()?;
    module.add_class::<UserMapping>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new(py, "user")?;
    module.add_class::<ManagementUser>()?;
    module.add_class::<ObjectUser>()?;
    module.add_class::<UserTag>()?;
    m.add_submodule(&module)?;

    Ok(())
}
