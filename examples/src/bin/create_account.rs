use objectscale_client::client::ManagementClient;
use objectscale_client::iam::{AccountBuilder, Tag};

fn main() {
    let endpoint = "https://10.225.108.186:443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client = ManagementClient::new(endpoint, username, password, insecure);
    let account = AccountBuilder::default()
        .alias("test")
        .encryption_enabled(true)
        .description("test")
        .tags(vec![Tag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("account");
    let account = client.create_account(account).expect("create account");
    println!("Created account: {:?}", account);
}
