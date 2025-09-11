use objectscale_client::client::ManagementClient;
use objectscale_client::provisioning::BucketTag;

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
    //bucket.auto_commit_period = 200;
    bucket.retention = 250;
    bucket.min_max_governor.enforce_retention = true;
    bucket.min_max_governor.maximum_fixed_retention = 300;
    bucket.default_object_lock_retention_mode = "COMPLIANCE".to_string();
    bucket.default_object_lock_retention_years = 0;
    bucket.default_object_lock_retention_days = 1;
    let state = client.update_bucket(bucket).expect("update bucket");

    println!("Update bucket: {:?}", state);
}
