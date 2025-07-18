use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let namespace = "ns1";
    let name_prefix = "";
    //let name_prefix = "r*";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let buckets = client
        .list_buckets(namespace, name_prefix)
        .expect("list buckets");
    println!("List buckets: {:?}", buckets);
}
