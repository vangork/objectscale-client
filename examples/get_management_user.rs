use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let id = "luis_user";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let management_user = client.get_management_user(id).expect("get management user");
    println!("Get management user: {:?}", management_user);
}
