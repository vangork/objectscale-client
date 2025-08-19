use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let id = "luis_namespace";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let namespace = client.get_namespace(id).expect("get namespace");
    println!("Get namespace: {:?}", namespace);
}
