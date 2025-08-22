use objectscale_client::client::ManagementClient;

fn main() {
    let endpoint = "https://10.225.108.217:4443";
    let username = "root";
    let password = "Password123!";
    let insecure = true;

    let id = "urn:storageos:ReplicationGroupInfo:0e953ad1-94a5-4eb1-825a-d58d29e85434:global";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");

    let rp = client
        .get_replication_group(id)
        .expect("get replication group");
    println!("Get replication group: {:?}", rp);

    let rps = client
        .list_replication_groups()
        .expect("list replication groups");
    println!("List replication groups: {:?}", rps);
}
