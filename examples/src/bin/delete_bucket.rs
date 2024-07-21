use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let name = "test";
    let namespace = "osai0a9250592a131336";

    let objectstore_endpoint = "https://10.225.108.187:4443";

    let management_client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut objectstore_client = management_client
        .new_objectstore_client(&objectstore_endpoint)
        .expect("objectstore client");

    objectstore_client
        .delete_bucket(name, namespace, false)
        .expect("delete bucket");
    println!("Deleted bucket: {:?}", name);
}
