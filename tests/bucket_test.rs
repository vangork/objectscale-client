mod common;
use objectscale_client::bucket::{BucketBuilder, BucketTag};
use objectscale_client::{iam::AccountBuilder, tenant::TenantBuilder};

#[test]
fn test_bucket() {
    let mut management_client = common::create_management_client();
    let mut objectstore_client = common::create_objectstore_client();

    let account_name = "testbucket";
    let account = AccountBuilder::default()
        .alias(account_name)
        .encryption_enabled(false)
        .build()
        .expect("build account");
    let account = management_client
        .create_account(account)
        .expect("create account");

    let tenant_alias = "testbucket";
    let tenant = TenantBuilder::default()
        .alias(tenant_alias)
        .id(&account.account_id)
        .is_encryption_enabled(false)
        .build()
        .expect("build tenant");
    let _ = objectstore_client
        .create_tenant(tenant)
        .expect("create tenant");

    let bucket_name = "testbucket";
    let expiration = -1;
    let bucket = BucketBuilder::default()
        .name(bucket_name)
        .namespace(&account.account_id)
        .audit_delete_expiration(expiration)
        .tags(vec![BucketTag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("build bucket");
    let _ = objectstore_client
        .create_bucket(bucket)
        .expect("create bucket");

    let mut bucket = objectstore_client
        .get_bucket(&bucket_name, &account.account_id)
        .expect("get bucket");
    assert_eq!(bucket.name, bucket_name);
    assert_eq!(bucket.namespace, account.account_id);
    assert_eq!(bucket.audit_delete_expiration, expiration);
    assert_eq!(bucket.tags.len(), 1);

    let new_expiration = 0;
    bucket.audit_delete_expiration = new_expiration;
    let bucket = objectstore_client
        .update_bucket(bucket)
        .expect("update bucket");
    assert_eq!(bucket.audit_delete_expiration, new_expiration);
    assert_eq!(bucket.name, bucket_name);
    assert_eq!(bucket.namespace, account.account_id);
    assert_eq!(bucket.tags.len(), 1);

    let buckets = objectstore_client
        .list_buckets(&account.account_id, "")
        .expect("list buckets");
    assert_ne!(buckets.len(), 0);

    objectstore_client
        .delete_bucket(&bucket_name, &account.account_id, false)
        .expect("delete bucket");

    objectstore_client
        .delete_tenant(&account.account_id)
        .expect("delete tenant");
    management_client
        .delete_account(&account.account_id)
        .expect("delete account");
}
