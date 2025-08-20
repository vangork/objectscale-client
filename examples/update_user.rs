use objectscale_client::client::ManagementClient;
use objectscale_client::iam::IamTag;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_user";
    let namespace = "ns1";
    let arn = "urn:ecs:iam:::policy/IAMFullAccess";

    let mut user = client.get_user(name, namespace).expect("get user");
    user.permissions_boundary.permissions_boundary_arn = arn.to_string();
    user.tags = vec![IamTag {
        key: "key2".to_string(),
        value: "value2".to_string(),
    }];
    let user = client.update_user(user).expect("update user");

    println!("Update user: {:?}", user);
}
