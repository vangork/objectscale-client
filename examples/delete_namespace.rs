use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_namespace";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    client.delete_namespace(name).expect("delete namespace");
    println!("Deleted namespace: {:?}", name);
}
