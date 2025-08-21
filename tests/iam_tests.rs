mod common;
use objectscale_client::iam::{IamTag, PermissionsBoundary, RoleBuilder, UserBuilder};
use objectscale_client::tenancy::NamespaceBuilder;

#[test]
fn test_role() {
    let mut client = common::create_management_client();

    let namespace_name = "test_role";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .build()
        .expect("build namespace");
    let namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let role_name = "test_role";
    let description = "test role description";
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
        .namespace(namespace_name)
        .build()
        .expect("role");
    let _ = client.create_role(role).expect("create role");

    let mut role = client
        .get_role(role_name, namespace_name)
        .expect("get role");
    assert_eq!(role.role_name, role_name);
    assert_eq!(role.description, description);
    assert_eq!(role.max_session_duration, duration);
    assert_eq!(role.namespace, namespace_name);
    assert_eq!(role.permissions_boundary.permissions_boundary_arn, arn);
    assert_eq!(role.tags.len(), 1);

    let new_duration = 7200;
    let new_description = "newtestrole description";
    role.max_session_duration = new_duration;
    role.description = new_description.to_string();
    let role = client.update_role(role).expect("update role");
    assert_eq!(role.role_name, role_name);
    assert_eq!(role.max_session_duration, new_duration);
    assert_eq!(role.description, new_description);
    assert_eq!(role.namespace, namespace_name);
    assert_eq!(role.permissions_boundary.permissions_boundary_arn, arn);
    assert_eq!(role.tags.len(), 1);

    let roles = client.list_roles(namespace_name).expect("list roles");
    assert_eq!(roles.len(), 1);

    client
        .delete_role(role_name, namespace_name)
        .expect("delete role");

    let roles = client.list_roles(namespace_name).expect("list roles");
    assert_eq!(roles.len(), 0);

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}
