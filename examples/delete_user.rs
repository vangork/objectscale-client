use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let user_name = "luis_user";
    let namespace = "ns1";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    client
        .delete_user(user_name, namespace)
        .expect("delete user");
    println!("Deleted user: {}", user_name);
}
