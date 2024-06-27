mod common;
use objectscale_client::iam::AccountBuilder;

#[test]
fn test_bucket() {
    let mut client = common::create_management_client();
    let name = "test1";
    let account = AccountBuilder::default()
        .alias(name)
        .encryption_enabled(false)
        .description(name)
        .build()
        .expect("build account");
    let account = client.create_account(account).expect("create account");

    let account = client
        .get_account(&account.account_id)
        .expect("get account");
    assert_eq!(account.alias, name);
    assert_eq!(account.description, name);
    assert_eq!(account.encryption_enabled, false);
    assert_eq!(account.tags.len(), 0);

    let resp = client.delete_account(&account.account_id);
    assert!(resp.is_ok());
}
