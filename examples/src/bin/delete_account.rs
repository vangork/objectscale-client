use objectscale_client::api_client::APIClient;

fn main() {
    let endpoint = "https://10.225.108.186:443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let account = "osaidbcb34792fb4ea3a";

    let mut client = APIClient::new(endpoint, username, password, insecure);
    client.delete_account(account).expect("delete account");
    println!("Deleted account: {}", account);
}
