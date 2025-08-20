use objectscale_client::client::ManagementClient;
use objectscale_client::user::{ObjectUserBuilder, UserTag};

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_user";
    let namespace = "ns1";

    let user = ObjectUserBuilder::default()
        .name(name)
        .namespace(namespace)
        .tag(vec![UserTag {
            name: "name1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("new object user");
    let user = client.create_object_user(user).expect("create user");

    println!("Created object user: {:?}", user);
}
