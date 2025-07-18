use objectscale_client::client::ManagementClient;
use objectscale_client::iam::AccessKeyBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let user_name = "luis";
    let namespace = "osai0a9250592a131336";

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

    let access_keys = client
        .list_access_keys(user_name, namespace)
        .expect("list access keys");
    println!("List access keys: {:?}", access_keys);

    access_key.status = "Inactive".to_string();
    let access_key = client
        .update_access_key(access_key)
        .expect("update access key");
    println!("Updated access key: {:?}", access_key);

    client
        .delete_access_key(&access_key.access_key_id, user_name, namespace)
        .expect("delete access key");
    println!("Deleted access key: {}", access_key.access_key_id);

    let access_keys = client
        .list_access_keys(user_name, namespace)
        .expect("list access keys");
    println!("List access keys: {:?}", access_keys);
}
