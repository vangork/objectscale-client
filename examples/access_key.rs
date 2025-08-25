use objectscale_client::client::ManagementClient;
use objectscale_client::iam::AccessKeyBuilder;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let user_name = "luis_user";
    let namespace = "ns1";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let access_key = AccessKeyBuilder::default()
        .user_name(user_name)
        .namespace(namespace)
        .build()
        .expect("access key");
    let mut access_key = client
        .create_access_key(access_key)
        .expect("create access key");
    println!("Created access key: {:?}", access_key);
    let access_key_id = access_key.access_key_id.clone();

    access_key.status = "Inactive".to_string();
    let state = client
        .update_access_key(access_key)
        .expect("update access key");
    println!("Updated access key: {:?}", state);

    let access_keys = client
        .list_access_keys(user_name, namespace)
        .expect("list access keys");
    println!("List access keys: {:?}", access_keys);

    client
        .delete_access_key(&access_key_id, user_name, namespace)
        .expect("delete access key");
    println!("Deleted access key: {}", &access_key_id);

    let access_keys = client
        .list_access_keys(user_name, namespace)
        .expect("list access keys");
    println!("List access keys: {:?}", access_keys);
}
