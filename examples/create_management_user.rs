use objectscale_client::client::ManagementClient;
use objectscale_client::user::ManagementUserBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_user";
    let password = "Password123!";

    let user = ManagementUserBuilder::default()
        .user_id(name)
        .password(password)
        .is_system_admin(true)
        .build()
        .expect("new management user");
    let user = client.create_management_user(user).expect("create user");

    println!("Created management user: {:?}", user);
}
