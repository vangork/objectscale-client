use objectscale_client::client::ManagementClient;
use objectscale_client::iam::AccountAccessKeyBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let account_id = "osai0a9250592a131336";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let account_access_key = AccountAccessKeyBuilder::default()
        .account_id(account_id)
        .build()
        .expect("account access key");
    let mut account_access_key = client
        .create_account_access_key(account_access_key)
        .expect("create account access key");
    println!("Created access key: {:?}", account_access_key);

    let account_access_keys = client
        .list_account_access_keys(account_id)
        .expect("list account access key");
    println!("List access keys: {:?}", account_access_keys);

    account_access_key.status = "Inactive".to_string();
    let account_access_key = client
        .update_account_access_key(account_access_key)
        .expect("update account access key");
    println!("Updated access key: {:?}", account_access_key);

    client
        .delete_account_access_key(&account_access_key.access_key_id, account_id)
        .expect("delete account access key");
    println!("Deleted access key: {}", account_access_key.access_key_id);

    let account_access_keys = client
        .list_account_access_keys(&account_id)
        .expect("list account access key");
    println!("List access keys: {:?}", account_access_keys);
}
