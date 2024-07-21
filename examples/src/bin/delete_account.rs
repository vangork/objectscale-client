use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let account_id = "osai74a971da08113120";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    client.delete_account(account_id).expect("delete account");
    println!("Deleted account: {}", account_id);
}
