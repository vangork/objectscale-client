use objectscale_client::bucket::{BucketBuilder, BucketTag, MetaData, SearchMetaData};
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
        .search_metadata(search_metadata)
        .build()
        .expect("new bucket");
    let bucket = client.create_bucket(bucket).expect("create bucket");

    println!("Created bucket: {:?}", bucket);
}
