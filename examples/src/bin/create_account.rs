use objectscale_client::api_client::APIClient;

fn main() {
    let endpoint = "https://10.225.108.186:443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client = APIClient::new(endpoint, username, password, insecure);
    let account = client.create_account("test").expect("create account");
    println!("Created account: {:?}", account);
}
