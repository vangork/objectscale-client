use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_user";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    client
        .delete_management_user(name)
        .expect("delete management user");
    println!("Deleted management user: {:?}", name);
}
