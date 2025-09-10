use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.151:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_user";
    let namespace = "ns1";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    client
        .delete_object_user(name, namespace)
        .expect("delete object user");
    println!("Deleted object user: {:?}", name);
}
