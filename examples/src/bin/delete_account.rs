use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.186:443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let account = "osaifed1dd997e8458e9";

    let mut client = ManagementClient::new(endpoint, username, password, insecure);
    client.delete_account(account).expect("delete account");
    println!("Deleted account: {}", account);
}
