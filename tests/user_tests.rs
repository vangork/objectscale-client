mod common;
use objectscale_client::tenancy::NamespaceBuilder;
use objectscale_client::user::{ManagementUserBuilder, ObjectUserBuilder, UserTag};

const REPLICATION_GROUP: &str =
    "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";

#[test]
fn test_management_user() {
    let mut client = common::create_management_client();

    let name = "user_test_management_user";
    let password = "Password123!";

    let user = ManagementUserBuilder::default()
        .user_id(name)
        .password(password)
        .build()
        .expect("new management user");
    let mut user = client
        .create_management_user(user)
        .expect("create management user");
    assert_eq!(user.is_locked, false);
    assert_eq!(user.user_id, name);
    assert_eq!(user.is_security_admin, false);

    user.is_security_admin = true;
    user.is_system_admin = true;
    user.is_system_monitor = true;

    let statu = client
        .update_management_user(user)
        .expect("update management user");
    assert_eq!(statu, true);

    let user = client
        .get_management_user(name)
        .expect("get management user");
    assert_eq!(user.is_system_admin, true);
    assert_eq!(user.is_system_monitor, true);
    assert_eq!(user.is_security_admin, true);

    let users = client
        .list_management_users()
        .expect("list management users");
    assert!(users.contains(&user));

    client
        .delete_management_user(name)
        .expect("delete management user");
}

#[test]
fn test_object_user() {
    let mut client = common::create_management_client();

    let namespace_name = "user_test_object_user";
    let namespace = NamespaceBuilder::default()
        .name(namespace_name)
        .default_data_services_vpool(REPLICATION_GROUP)
        .build()
        .expect("build namespace");
    let namespace = client
        .create_namespace(namespace)
        .expect("create namespace");

    let name = "user_test_object_user";
    let user = ObjectUserBuilder::default()
        .name(name)
        .namespace(namespace_name)
        .build()
        .expect("new object user");
    let mut user = client.create_object_user(user).expect("create object user");
    assert_eq!(user.name, name);
    assert_eq!(user.namespace, namespace_name);
    assert_eq!(user.tag.len(), 0);
    assert_eq!(user.locked, false);

    let tags = vec![UserTag {
        name: "name1".to_string(),
        value: "value1".to_string(),
    }];

    user.tag = tags.clone();
    let state = client.update_object_user(user).expect("update object user");
    assert_eq!(state, true);

    let user = client
        .get_object_user(name, namespace_name)
        .expect("get object user");
    assert_eq!(user.tag, tags);

    let users = client.list_object_users().expect("list object users");
    assert!(users.contains(&user));

    client
        .delete_object_user(name, namespace_name)
        .expect("delete object user");

    client
        .delete_namespace(&namespace.id)
        .expect("delete namespace");
}
