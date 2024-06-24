use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.186:443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let account_id = "osai146547798ea4bf92";

    let mut client = ManagementClient::new(endpoint, username, password, insecure);
    client.delete_account(account_id).expect("delete account");
    println!("Deleted account: {}", account_id);
}
