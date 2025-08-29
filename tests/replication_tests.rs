mod common;

const RG_ID: &str =
    "urn:storageos:ReplicationGroupInfo:b1733748-5695-4330-bb95-5f98df33cfdf:global";

#[test]
fn test_replication_group() {
    let mut client = common::create_management_client();

    let mut rg = client
        .get_replication_group(RG_ID)
        .expect("get replication group");

    let new_name = "replication_test_replication_group".to_string();
    let new_description = "replication test replication group description".to_string();
    let enable_rebalancing = !(rg.enable_rebalancing);
    let is_allow_all_namespaces = !(rg.is_allow_all_namespaces);

    rg.name = new_name.clone();
    rg.description = new_description.clone();
    rg.enable_rebalancing = enable_rebalancing;
    rg.is_allow_all_namespaces = is_allow_all_namespaces;
    let state = client
        .update_replication_group(rg)
        .expect("update replication group");
    assert_eq!(state, true);

    let get_rg = client
        .get_replication_group(RG_ID)
        .expect("get replication group");
    assert_eq!(get_rg.name, new_name);
    assert_eq!(get_rg.description, new_description);
    assert_eq!(get_rg.enable_rebalancing, enable_rebalancing);
    assert_eq!(get_rg.is_allow_all_namespaces, is_allow_all_namespaces);

    let rgs = client
        .list_replication_groups()
        .expect("list replication groups");

    assert!(rgs.contains(&get_rg));
}
