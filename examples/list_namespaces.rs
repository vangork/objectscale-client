use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name_prefix = "";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let namespaces = client
        .list_namespaces(name_prefix)
        .expect("list namespaces");
    println!("List namespaces: {:?}", namespaces);
}
