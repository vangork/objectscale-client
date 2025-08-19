mod common;
use objectscale_client::tenancy::NamespaceBuilder;

#[test]
fn test_tenancy() {
    let mut management_client = common::create_management_client();

    let namespace_name = "testtenancy";
    let namespace_block_size: i64 = 5;

    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .is_encryption_enabled(true)
        .is_compliance_enabled(true)
        .default_bucket_block_size(namespace_block_size)
        .build()
        .expect("build namespace");
    let namespace = management_client
        .create_namespace(namespace)
        .expect("create namespace");

    let mut namespace = management_client
        .get_namespace(&namespace.id)
        .expect("get namespace");
    assert_eq!(namespace.name, namespace_name);
    assert_eq!(namespace.default_bucket_block_size, namespace_block_size);
    assert_eq!(namespace.is_encryption_enabled, true);
    assert_eq!(namespace.is_compliance_enabled, true);

    let new_namespace_block_size: i64 = 10;
    namespace.default_bucket_block_size = new_namespace_block_size;
    let namespace = management_client
        .update_namespace(namespace)
        .expect("update namespace");
    assert_eq!(
        namespace.default_bucket_block_size,
        new_namespace_block_size
    );
    assert_eq!(namespace.is_encryption_enabled, true);
    assert_eq!(namespace.is_compliance_enabled, true);

    let namespaces = management_client
        .list_namespaces("")
        .expect("list namespaces");
    assert_ne!(namespaces.len(), 0);

    management_client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}
