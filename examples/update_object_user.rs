use objectscale_client::client::ManagementClient;
use objectscale_client::user::UserTag;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_user";
    let namespace = "ns1";

    let mut user = client
        .get_object_user(name, namespace)
        .expect("get object user");
    user.locked = true;
    user.tag = vec![UserTag {
        name: "name2".to_string(),
        value: "value2".to_string(),
    }];
    let state = client.update_object_user(user).expect("update object user");

    println!("Update object user: {:?}", state);
}
