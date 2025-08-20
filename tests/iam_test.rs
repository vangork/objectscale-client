mod common;
use objectscale_client::iam::{IamTag, PermissionsBoundary, RoleBuilder, UserBuilder};

#[test]
fn test_role() {
    let mut management_client = common::create_management_client();

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
        .tags(vec![IamTag {
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
}
