use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let id = "urn:storageos:ReplicationGroupInfo:b1733748-5695-4330-bb95-5f98df33cfdf:global";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let mut rg = client
        .get_replication_group(id)
        .expect("get replication group");
    println!("Get replication group: {:?}", rg);

    rg.name = "luis333".to_string();
    rg.description = "luis333 description".to_string();
    rg.enable_rebalancing = true;
    rg.is_allow_all_namespaces = true;
    let state = client
        .update_replication_group(&rg)
        .expect("update replication group");
    println!("Updated replication group: {:?}", state);

    let rg = client
        .get_replication_group(id)
        .expect("get replication group");
    println!("Get replication group: {:?}", rg);

    // let rgs = client
    //     .list_replication_groups()
    //     .expect("list replication groups");
    // println!("List replication groups: {:?}", rgs);
}
