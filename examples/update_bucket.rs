use objectscale_client::bucket::BucketTag;
use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let name = "luis_bucket";
    let namespace = "ns1";

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut bucket = client.get_bucket(name, namespace).expect("get bucket");
    bucket.owner = "object_admin1".to_string();
    bucket.tags = vec![BucketTag {
        key: "key2".to_string(),
        value: "value2".to_string(),
    }];
    let bucket = client.update_bucket(bucket).expect("update bucket");

    println!("Update bucket: {:?}", bucket);
}
