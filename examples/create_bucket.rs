use objectscale_client::bucket::{BucketBuilder, BucketTag};
use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_bucket";
    let namespace = "ns1";

    let bucket = BucketBuilder::default()
        .name(name)
        .namespace(namespace)
        .tags(vec![BucketTag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("bucket");
    let bucket = client.create_bucket(bucket).expect("create bucket");

    println!("Created bucket: {:?}", bucket);
}
