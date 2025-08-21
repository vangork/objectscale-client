mod common;
use objectscale_client::tenancy::NamespaceBuilder;
use objectscale_client::user::{ManagementUserBuilder, ObjectUserBuilder, UserTag};

#[test]
fn test_management_user() {
    let mut client = common::create_management_client();

    let name = "test_management_user";
    let password = "Password123!";

    let user = ManagementUserBuilder::default()
        .user_id(name)
        .password(password)
        .is_system_admin(true)
        .build()
        .expect("new management user");
    let new_user = client
        .create_management_user(user)
        .expect("create management user");

    let user = client
        .get_management_user(name)
        .expect("get management user");
    assert_eq!(new_user, user);

    client
        .delete_management_user(name)
        .expect("delete management user");
}

#[test]
fn test_object_user() {
    let mut client = common::create_management_client();

    let namespace_name = "test_object_user";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .build()
        .expect("build namespace");
    let namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let name = "test_object_user";
    let user = ObjectUserBuilder::default()
        .name(name)
        .namespace(namespace_name)
        .tag(vec![UserTag {
            name: "name1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("new object user");
    let new_user = client.create_object_user(user).expect("create object user");

    let user = client
        .get_object_user(name, namespace_name)
        .expect("get object user");
    assert_eq!(new_user, user);

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}
