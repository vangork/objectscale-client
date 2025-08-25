use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_user";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut user = client
        .get_management_user(name)
        .expect("get management user");
    user.is_system_admin = true;
    user.is_system_monitor = true;
    user.is_security_admin = true;
    let state = client
        .update_management_user(user)
        .expect("update management user");

    println!("Update management user: {:?}", state);
}
