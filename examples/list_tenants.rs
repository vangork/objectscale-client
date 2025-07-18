use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let objectstore_endpoint = "https://10.225.108.187:4443";
    let account_prefix = "";
    //let account_prefix = "yu*";

    let management_client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut objectstore_client = management_client
        .new_objectstore_client(&objectstore_endpoint)
        .expect("objectstore client");
    let tenants = objectstore_client
        .list_tenants(account_prefix)
        .expect("list tenants");
    println!("List tenants: {:?}", tenants);
}
