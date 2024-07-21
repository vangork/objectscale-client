mod common;
use objectscale_client::iam::{AccountBuilder, PermissionsBoundary, RoleBuilder, Tag};

#[test]
fn test_account() {
    let mut management_client = common::create_management_client();

    let name = "testaccount";
    let description = "testaccount description";
    let encryption = true;

    let account = AccountBuilder::default()
        .alias(name)
        .encryption_enabled(encryption)
        .description(description)
        .tags(vec![Tag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("build account");
    let account = management_client
        .create_account(account)
        .expect("create account");

    let mut account = management_client
        .get_account(&account.account_id)
        .expect("get account");
    assert_eq!(account.alias, name);
    assert_eq!(account.description, description);
    assert_eq!(account.encryption_enabled, encryption);
    assert_eq!(account.tags.len(), 1);

    let new_name = "newtestaccount";
    let new_description = "newtestaccount description";
    account.alias = new_name.to_string();
    account.description = new_description.to_string();
    let account = management_client
        .update_account(account)
        .expect("update account");
    assert_eq!(account.alias, new_name);
    assert_eq!(account.description, new_description);
    assert_eq!(account.encryption_enabled, encryption);
    assert_eq!(account.tags.len(), 1);

    let accounts = management_client.list_accounts().expect("list accounts");
    assert_ne!(accounts.len(), 0);

    management_client
        .delete_account(&account.account_id)
        .expect("delete account");

    let account = AccountBuilder::default()
        .alias("!test-123")
        .build()
        .expect("build account");
    let result = management_client.create_account(account);
    assert!(result.is_err());
}

#[test]
fn test_role() {
    let mut management_client = common::create_management_client();

    let account_name = "testrole";
    let account = AccountBuilder::default()
        .alias(account_name)
        .build()
        .expect("build account");
    let account = management_client
        .create_account(account)
        .expect("create account");

    let role_name = "testrole";
    let description = "testrole description";
    let duration = 9600;
    let arn = "urn:osc:iam:::policy/CRRFullAccess";
    let assume_doc = r#"{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}"#;

    let role = RoleBuilder::default()
        .role_name(role_name)
        .description(description)
        .max_session_duration(duration)
        .assume_role_policy_document(assume_doc)
        .permissions_boundary(PermissionsBoundary {
            permissions_boundary_arn: arn.to_string(),
            permissions_boundary_type: "".to_string(),
        })
        .tags(vec![Tag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .namespace(&account.account_id)
        .build()
        .expect("role");
    let _ = management_client.create_role(role).expect("create role");

    let mut role = management_client
        .get_role(role_name, &account.account_id)
        .expect("get role");
    assert_eq!(role.role_name, role_name);
    assert_eq!(role.description, description);
    assert_eq!(role.max_session_duration, duration);
    assert_eq!(role.namespace, account.account_id);
    assert_eq!(role.permissions_boundary.permissions_boundary_arn, arn);
    assert_eq!(role.tags.len(), 1);

    let new_duration = 7200;
    let new_description = "newtestrole description";
    role.max_session_duration = new_duration;
    role.description = new_description.to_string();
    let role = management_client.update_role(role).expect("update role");
    assert_eq!(role.role_name, role_name);
    assert_eq!(role.max_session_duration, new_duration);
    assert_eq!(role.description, new_description);
    assert_eq!(role.namespace, account.account_id);
    assert_eq!(role.permissions_boundary.permissions_boundary_arn, arn);
    assert_eq!(role.tags.len(), 1);

    let roles = management_client
        .list_roles(&account.account_id)
        .expect("list roles");
    assert_eq!(roles.len(), 1);

    management_client
        .delete_role(role_name, &account.account_id)
        .expect("delete role");

    let roles = management_client
        .list_roles(&account.account_id)
        .expect("list roles");
    assert_eq!(roles.len(), 0);

    management_client
        .delete_account(&account.account_id)
        .expect("delete account");
}
