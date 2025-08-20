use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_user";
    let namespace = "ns1";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let user = client.get_user(name, namespace).expect("get user");
    println!("Get user: {:?}", user);
}
