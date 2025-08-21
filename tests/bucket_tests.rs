mod common;
use objectscale_client::bucket::{BucketBuilder, BucketTag};
use objectscale_client::tenancy::NamespaceBuilder;

#[test]
fn test_bucket() {
    let mut management_client = common::create_management_client();

    let namespace_name = "test_bucket";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .build()
        .expect("build namespace");
    let namespace = management_client
        .create_namespace(namespace)
        .expect("create namespace");

    let bucket_name = "testbucket";
    let expiration = -1;
    let bucket = BucketBuilder::default()
        .name(bucket_name)
        .namespace(&namespace.id)
        .audit_delete_expiration(expiration)
        .tags(vec![BucketTag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("build bucket");
    let _ = management_client
        .create_bucket(bucket)
        .expect("create bucket");

    let mut bucket = management_client
        .get_bucket(&bucket_name, &namespace.id)
        .expect("get bucket");
    assert_eq!(bucket.name, bucket_name);
    assert_eq!(bucket.namespace, namespace.id);
    assert_eq!(bucket.audit_delete_expiration, expiration);
    assert_eq!(bucket.tags.len(), 1);

    let new_expiration = 0;
    bucket.audit_delete_expiration = new_expiration;
    let bucket = management_client
        .update_bucket(bucket)
        .expect("update bucket");
    assert_eq!(bucket.audit_delete_expiration, new_expiration);
    assert_eq!(bucket.name, bucket_name);
    assert_eq!(bucket.namespace, namespace.id);
    assert_eq!(bucket.tags.len(), 1);

    let buckets = management_client
        .list_buckets(&namespace.id, "")
        .expect("list buckets");
    assert_ne!(buckets.len(), 0);

    management_client
        .delete_bucket(&bucket_name, &namespace.id, false)
        .expect("delete bucket");

    management_client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}
