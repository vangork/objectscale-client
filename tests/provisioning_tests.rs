mod common;
use objectscale_client::provisioning::{BucketBuilder, BucketTag};
use objectscale_client::tenancy::NamespaceBuilder;

const REPLICATION_GROUP: &str =
    "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";

#[test]
fn test_bucket() {
    let mut management_client = common::create_management_client();

    let namespace_name = "provisioning_test_bucket";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("new namespace");
    let namespace = management_client
        .create_namespace(namespace)
        .expect("create namespace");

    let bucket_name = "provisioning_test_bucket";
    let bucket = BucketBuilder::default()
        .name(bucket_name)
        .namespace(&namespace.id)
        .build()
        .expect("new bucket");
    let mut bucket = management_client
        .create_bucket(bucket)
        .expect("create bucket");
    assert_eq!(bucket.name, bucket_name);
    assert_eq!(bucket.namespace, namespace.id);
    assert_eq!(bucket.tags.len(), 0);

    let tags = vec![BucketTag {
        key: "key1".to_string(),
        value: "value1".to_string(),
    }];
    bucket.tags = tags.clone();

    let state = management_client
        .update_bucket(bucket)
        .expect("update bucket");
    assert_eq!(state, true);

    let bucket = management_client
        .get_bucket(&bucket_name, &namespace.id)
        .expect("get bucket");
    assert_eq!(bucket.name, bucket_name);
    assert_eq!(bucket.namespace, namespace.id);
    assert_eq!(bucket.tags, tags);

    let buckets = management_client
        .list_buckets(&namespace.id, "")
        .expect("list buckets");
    assert!(buckets.contains(&bucket));

    management_client
        .delete_bucket(&bucket_name, &namespace.id, false)
        .expect("delete bucket");

    management_client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}
