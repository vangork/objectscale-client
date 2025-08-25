mod common;
use objectscale_client::tenancy::{
    Attribute, NamespaceBuilder, RetionClass, RetionClasses, UserMapping,
};

const REPLICATION_GROUP: &str =
    "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";

#[test]
fn test_namespace() {
    let mut management_client = common::create_management_client();

    let namespace_name = "tenancy_test_namespace";

    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let mut namespace = management_client
        .create_namespace(namespace)
        .expect("create namespace");
    assert_eq!(namespace.name, namespace_name);
    assert_eq!(namespace.default_bucket_block_size, -1);
    assert_eq!(namespace.is_encryption_enabled, false);
    assert_eq!(namespace.default_data_services_vpool, REPLICATION_GROUP);

    let namespace_id = namespace.id.clone();
    let new_namespace_block_size: i64 = 10;
    let user_mappings = vec![UserMapping {
        attributes: vec![Attribute {
            key: "aa".to_string(),
            value: vec!["aa".to_string()],
        }],
        domain: "aa".to_string(),
        groups: vec!["aa".to_string()],
    }];
    let retention_classes = RetionClasses {
        retention_class: vec![RetionClass {
            name: "r1".to_string(),
            period: 1,
        }],
    };

    namespace.default_bucket_block_size = new_namespace_block_size;
    namespace.user_mapping = user_mappings.clone();
    namespace.block_size = 2;
    namespace.notification_size = 2;
    namespace.retention_classes = retention_classes.clone();
    namespace.is_stale_allowed = true;

    let state = management_client
        .update_namespace(namespace)
        .expect("update namespace");
    assert_eq!(state, true);

    let namespace = management_client
        .get_namespace(&namespace_id)
        .expect("get namespace");
    assert_eq!(namespace.name, namespace_name);
    assert_eq!(
        namespace.default_bucket_block_size,
        new_namespace_block_size
    );
    assert_eq!(namespace.user_mapping, user_mappings);
    assert_eq!(namespace.block_size, 2);
    assert_eq!(namespace.notification_size, 2);
    assert_eq!(namespace.retention_classes, retention_classes);
    assert_eq!(namespace.is_stale_allowed, true);

    let namespaces = management_client
        .list_namespaces("")
        .expect("list namespaces");
    assert!(namespaces.contains(&namespace));

    management_client
        .delete_namespace(&namespace_id)
        .expect("delete namespace");
}
