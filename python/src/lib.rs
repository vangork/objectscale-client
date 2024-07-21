mod bucket;
mod client;
mod iam;
mod tenant;

use bucket::{Bucket, BucketTag, Link, MetaData, MinMaxGovernor, SearchMetaData};
use client::{ManagementClient, ObjectstoreClient};
use iam::{
    AccessKey, Account, AccountAccessKey, EntitiesForPolicy, Group, GroupPolicyAttachment,
    LoginProfile, PermissionsBoundary, Policy, Role, RolePolicyAttachment, Tag, User,
    UserGroupMembership, UserPolicyAttachment,
};
use tenant::Tenant;

use pyo3::prelude::*;

#[pymodule]
fn objectscale_client(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new_bound(py, "bucket")?;
    module.add_class::<Bucket>()?;
    module.add_class::<BucketTag>()?;
    module.add_class::<Link>()?;
    module.add_class::<MetaData>()?;
    module.add_class::<MinMaxGovernor>()?;
    module.add_class::<SearchMetaData>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new_bound(py, "client")?;
    module.add_class::<ManagementClient>()?;
    module.add_class::<ObjectstoreClient>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new_bound(py, "iam")?;
    module.add_class::<AccessKey>()?;
    module.add_class::<Account>()?;
    module.add_class::<AccountAccessKey>()?;
    module.add_class::<EntitiesForPolicy>()?;
    module.add_class::<Group>()?;
    module.add_class::<GroupPolicyAttachment>()?;
    module.add_class::<LoginProfile>()?;
    module.add_class::<PermissionsBoundary>()?;
    module.add_class::<Policy>()?;
    module.add_class::<Role>()?;
    module.add_class::<RolePolicyAttachment>()?;
    module.add_class::<Tag>()?;
    module.add_class::<User>()?;
    module.add_class::<UserGroupMembership>()?;
    module.add_class::<UserPolicyAttachment>()?;
    m.add_submodule(&module)?;

    let module = PyModule::new_bound(py, "tenant")?;
    module.add_class::<Tenant>()?;
    m.add_submodule(&module)?;

    Ok(())
}
