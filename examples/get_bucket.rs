use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let objectstore_endpoint = "https://10.225.108.187:4443";
    let name = "rust";
    let namespace = "osai0a9250592a131336";

    let management_client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut objectstore_client = management_client
        .new_objectstore_client(&objectstore_endpoint)
        .expect("objectstore client");
    let bucket = objectstore_client
        .get_bucket(name, namespace)
        .expect("get bucket");
    println!("Get bucket: {:?}", bucket);
}
