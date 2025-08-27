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

#[test]
fn test_vdc() {
    let mut management_client = common::create_management_client();

    let vdc_name = "vdc1";
    let vdc = management_client.get_vdc(vdc_name).expect("get vdc");
    assert_eq!(vdc.name, vdc_name);

    let vdcs = management_client.list_vdcs().expect("list vdcs");
    assert!(vdcs.contains(&vdc));
}

#[test]
fn test_vdc_keystore() {
    let mut management_client = common::create_management_client();

    let store = management_client
        .get_vdc_keystore()
        .expect("get vdc keystore");
    assert!(!store.chain.is_empty());
}

#[test]
fn storage_pool() {
    let mut management_client = common::create_management_client();

    let sp_id = "urn:storageos:VirtualArray:2a36f1a7-4281-453d-8927-788f8033416b";
    let mut sp = management_client
        .get_storage_pool(sp_id)
        .expect("get storage pool");
    assert_eq!(sp.id, sp_id);

    let original_sp = sp.clone();

    sp.name = "sp2".to_string();
    sp.description = "sp2 description".to_string();
    sp.warning_alert_at = 35;
    sp.error_alert_at = -1;
    sp.critical_alert_at = -1;
    let state = management_client
        .update_storage_pool(sp)
        .expect("update storage pool");
    assert_eq!(state, true);

    let sp = management_client
        .get_storage_pool(sp_id)
        .expect("get storage pool");
    assert_eq!(sp.name, "sp2");
    assert_eq!(sp.description, "sp2 description");
    assert_eq!(sp.warning_alert_at, 35);
    assert_eq!(sp.error_alert_at, -1);
    assert_eq!(sp.critical_alert_at, -1);

    let _ = management_client
        .update_storage_pool(original_sp)
        .expect("update storage pool");

    let sp = management_client
        .get_storage_pool(sp_id)
        .expect("get storage pool");
    let sps = management_client
        .list_storage_pools()
        .expect("list storage pools");
    assert!(sps.contains(&sp));
}
