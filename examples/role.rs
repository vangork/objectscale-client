use objectscale_client::client::ManagementClient;
use objectscale_client::iam::{IamTag, PermissionsBoundary, RoleBuilder};

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let role_name = "luis_role";
    let namespace = "ns1";
    let arn = "urn:ecs:iam:::policy/ECSS3FullAccess";
    let new_arn = "urn:ecs:iam:::policy/IAMFullAccess";
    let assume_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:ecs:iam::ns1:root"]},"Action":"sts:AssumeRole"}]}"#;
    let new_assume_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:ecs:iam::ns1:user/luis"]},"Action":"sts:AssumeRole"}]}"#;

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let role = RoleBuilder::default()
        .role_name(role_name)
        .assume_role_policy_document(assume_doc)
        .permissions_boundary(PermissionsBoundary {
            permissions_boundary_arn: arn.to_string(),
            permissions_boundary_type: "".to_string(),
        })
        .tags(vec![IamTag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .namespace(namespace)
        .build()
        .expect("role");
    let mut role = client.create_role(role).expect("create role");
    println!("Created role: {:?}", role);

    role.description = "luis role".to_string();
    role.max_session_duration = 3600 * 2;
    role.permissions_boundary.permissions_boundary_arn = new_arn.to_string();
    role.assume_role_policy_document = new_assume_doc.to_string();
    role.tags = vec![IamTag {
        key: "key2".to_string(),
        value: "value2".to_string(),
    }];
    let state = client.update_role(role).expect("update role");
    println!("Updated role: {:?}", state);

    let role = client.get_role(role_name, namespace).expect("get role");
    println!("Get role: {:?}", role);

    client
        .delete_role(role_name, namespace)
        .expect("delete role");
    println!("Deleted role: {}", role_name);

    let roles = client.list_roles(namespace).expect("list roles");
    println!("List roles: {:?}", roles);
}
