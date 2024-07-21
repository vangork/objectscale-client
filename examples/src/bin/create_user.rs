use objectscale_client::client::ManagementClient;
use objectscale_client::iam::{PermissionsBoundary, Tag, UserBuilder};

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let user_name = "test";
    let namespace = "osai0a9250592a131336";
    let arn = "urn:osc:iam:::policy/CRRFullAccess";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let user = UserBuilder::default()
        .user_name(user_name)
        .namespace(namespace)
        .tags(vec![Tag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .permissions_boundary(PermissionsBoundary {
            permissions_boundary_arn: arn.to_string(),
            permissions_boundary_type: "".to_string(),
        })
        .build()
        .expect("user");
    let user = client.create_user(user).expect("create user");
    println!("Created user: {:?}", user);
}
