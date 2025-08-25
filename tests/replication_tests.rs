mod common;

const RG_ID: &str =
    "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";

#[test]
fn test_replication_group() {
    let mut client = common::create_management_client();

    let rg = client
        .get_replication_group(RG_ID)
        .expect("get replication group");

    let rgs = client
        .list_replication_groups()
        .expect("list replication groups");

    assert!(rgs.contains(&rg));
}
