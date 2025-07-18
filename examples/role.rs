use objectscale_client::client::ManagementClient;
use objectscale_client::iam::{PermissionsBoundary, RoleBuilder, Tag};

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let namespace = "osai0a9250592a131336";
    let role_name = "test";
    let arn = "urn:osc:iam:::policy/CRRFullAccess";
    let assume_doc = r#"{"Version":"2024-07-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["urn:osc:iam::osai0a9250592a131336:user/luis"]},"Action":"sts:AssumeRole"}]}"#;

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let role = RoleBuilder::default()
        .role_name(role_name)
        .assume_role_policy_document(assume_doc)
        .permissions_boundary(PermissionsBoundary {
            permissions_boundary_arn: arn.to_string(),
            permissions_boundary_type: "".to_string(),
        })
        .tags(vec![Tag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .namespace(namespace)
        .build()
        .expect("role");
    let role = client.create_role(role).expect("create role");
    println!("Created role: {:?}", role);

    let role = client.get_role(role_name, namespace).expect("get role");
    println!("Get role: {:?}", role);

    client
        .delete_role(role_name, namespace)
        .expect("delete role");
    println!("Deleted role: {}", role_name);

    let roles = client.list_roles(namespace).expect("list roles");
    println!("List roles: {:?}", roles);
}
