mod common;
use objectscale_client::iam::{AccountBuilder, Tag};

#[test]
fn test_account() {
    let mut client = common::create_management_client();
    let name = "test";
    let account = AccountBuilder::default()
        .alias(name)
        .encryption_enabled(true)
        .description(name)
        .tags(vec![Tag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("build account");
    let account = client.create_account(account).expect("create account");

    let account = client
        .get_account(&account.account_id)
        .expect("get account");
    assert_eq!(account.alias, name);
    assert_eq!(account.description, name);
    assert_eq!(account.encryption_enabled, true);
    assert_eq!(account.tags.len(), 1);

    let resp = client.delete_account(&account.account_id);
    assert!(resp.is_ok());
}
