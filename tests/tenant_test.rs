mod common;
use objectscale_client::iam::AccountBuilder;
use objectscale_client::tenant::TenantBuilder;

#[test]
fn test_tenant() {
    let mut management_client = common::create_management_client();
    let mut objectstore_client = common::create_objectstore_client();

    let account_name = "testtenant";
    let account = AccountBuilder::default()
        .alias(account_name)
        .build()
        .expect("build account");
    let account = management_client
        .create_account(account)
        .expect("create account");

    let tenant_alias = "testtenant";
    let tenant_block_size: i64 = 5;
    let tenant = TenantBuilder::default()
        .alias(tenant_alias)
        .id(&account.account_id)
        .is_encryption_enabled(true)
        .is_compliance_enabled(true)
        .default_bucket_block_size(tenant_block_size)
        .build()
        .expect("build tenant");
    let tenant = objectstore_client
        .create_tenant(tenant)
        .expect("create tenant");

    let mut tenant = objectstore_client
        .get_tenant(&tenant.id)
        .expect("get tenant");
    assert_eq!(tenant.alias, tenant_alias);
    assert_eq!(tenant.default_bucket_block_size, tenant_block_size);
    assert_eq!(tenant.id, account.account_id);
    assert_eq!(tenant.is_encryption_enabled, true);
    assert_eq!(tenant.is_compliance_enabled, true);

    let new_tenant_alias = "newtesttenant";
    let new_tenant_block_size: i64 = 10;
    tenant.alias = new_tenant_alias.to_string();
    tenant.default_bucket_block_size = new_tenant_block_size;
    let tenant = objectstore_client
        .update_tenant(tenant)
        .expect("update tenant");
    assert_eq!(tenant.alias, new_tenant_alias);
    assert_eq!(tenant.default_bucket_block_size, new_tenant_block_size);
    assert_eq!(tenant.id, account.account_id);
    assert_eq!(tenant.is_encryption_enabled, true);
    assert_eq!(tenant.is_compliance_enabled, true);

    let tenants = objectstore_client.list_tenants("").expect("list tenants");
    assert_ne!(tenants.len(), 0);

    objectstore_client
        .delete_tenant(&account.account_id)
        .expect("delete tenant");

    management_client
        .delete_account(&account.account_id)
        .expect("delete account");
}
