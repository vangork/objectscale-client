use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_namespace";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut namespace = client.get_namespace(name).expect("get namespace");
    namespace.block_size = -1;
    namespace.notification_size = -1;
    namespace.block_size_in_count = -1;
    namespace.notification_size_in_count = -1;
    namespace.retention_classes.retention_class[0].period = 2;
    let namespace = client
        .update_namespace(namespace)
        .expect("update namespace");

    println!("Update bucket: {:?}", namespace);
}
