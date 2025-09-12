use objectscale_client::client::ManagementClient;
use objectscale_client::provisioning::{
    BucketBuilder, BucketTag, MetaData, MinMaxGovernor, SearchMetaData,
};

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let mut client =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let name = "luis_bucket";
    let namespace = "ns1";

    let mut search_metadata = SearchMetaData::default();
    search_metadata.metadata.push(MetaData {
        datatype: "datetime".to_string(),
        name: "CreateTime".to_string(),
        r#type: "System".to_string(),
    });
    search_metadata.metadata.push(MetaData {
        datatype: "integer".to_string(),
        name: "x-amz-meta-size".to_string(),
        r#type: "User".to_string(),
    });

    let bucket = BucketBuilder::default()
        .name(name)
        .namespace(namespace)
        //.owner("object_admin1".to_string())
        .tags(vec![BucketTag {
            key: "key1".to_string(),
            value: "value1".to_string(),
        }])
        .auto_commit_period(100)
        // .fs_access_enabled(true)
        .retention(200)
        .min_max_governor(MinMaxGovernor {
            maximum_fixed_retention: 300,
            ..Default::default()
        })
        // .is_object_lock_enabled(true)
        // .default_object_lock_retention_mode("GOVERNANCE")
        // .default_object_lock_retention_years(1)
        // .default_group("luis")
        // .default_group_file_read_permission(true)
        // .default_group_dir_read_permission(true)
        // .versioning_status("")
        // .block_size(200)
        // .notification_size(100)
        // .block_size_in_count(50)
        // .notification_size_in_count(10)
        .audit_delete_expiration(100)
        .search_metadata(search_metadata)
        .build()
        .expect("build bucket");
    let bucket = client.create_bucket(bucket).expect("create bucket");

    println!("Created bucket: {:?}", bucket);
}
