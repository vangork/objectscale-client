use objectscale_client::client::ManagementClient;
use objectscale_client::tenancy::{Attribute, UserMapping};

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_namespace";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut namespace = client.get_namespace(name).expect("get namespace");
    namespace.default_bucket_block_size = 200;
    namespace.user_mapping = vec![UserMapping {
        attributes: vec![Attribute {
            key: "bb".to_string(),
            value: vec!["bb".to_string()],
        }],
        domain: "bb".to_string(),
        groups: vec!["bb".to_string()],
    }];
    namespace.block_size = -1;
    namespace.notification_size = -1;
    namespace.block_size_in_count = -1;
    namespace.notification_size_in_count = -1;
    namespace.retention_classes.retention_class[0].period = 2;
    let state = client
        .update_namespace(namespace)
        .expect("update namespace");

    println!("Update namespace: {:?}", state);
}
