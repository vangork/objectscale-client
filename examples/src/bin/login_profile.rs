use objectscale_client::client::ManagementClient;
use objectscale_client::iam::LoginProfileBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let user_name = "luis";
    let pwd = "luis";
    let namespace = "osai0a9250592a131336";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let login_profile = LoginProfileBuilder::default()
        .user_name(user_name)
        .password(pwd)
        .namespace(namespace)
        .build()
        .expect("login profile");

    let login_profile = client
        .create_login_profile(login_profile)
        .expect("create login profile");
    println!("Created login profile: {:?}", login_profile);

    let login_profile = client
        .get_login_profile(user_name, namespace)
        .expect("get login profile");
    println!("Got login profile: {:?}", login_profile);

    client
        .delete_login_profile(user_name, namespace)
        .expect("delete login profile");
    println!("Deleted login profile: {}", user_name);

    let login_profile = client.get_login_profile(user_name, namespace);
    println!("Got login profile: {:?}", login_profile);
}
