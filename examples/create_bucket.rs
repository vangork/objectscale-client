use objectscale_client::bucket::{BucketBuilder, BucketTag};
use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let name = "test";
    let namespace = "osai0a9250592a131336";

    let objectstore_endpoint = "https://10.225.108.187:4443";

    let management_client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let mut objectstore_client = management_client
        .new_objectstore_client(&objectstore_endpoint)
        .expect("objectstore client");

    let bucket = BucketBuilder::default()
        .name(name)
        .namespace(namespace)
        .tags(vec![BucketTag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .build()
        .expect("bucket");
    let bucket = objectstore_client
        .create_bucket(bucket)
        .expect("create bucket");

    println!("Created bucket: {:?}", bucket);
}
