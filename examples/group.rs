use objectscale_client::client::ManagementClient;
use objectscale_client::iam::GroupBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let namespace = "osai0a9250592a131336";
    let group_name = "test";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let group = GroupBuilder::default()
        .group_name(group_name)
        .namespace(namespace)
        .build()
        .expect("group");
    let group = client.create_group(group).expect("create group");
    println!("Created group: {:?}", group);

    let group = client.get_group(group_name, namespace).expect("get group");
    println!("Get group: {:?}", group);

    client
        .delete_group(group_name, namespace)
        .expect("delete group");
    println!("Deleted group: {}", group_name);

    let groups = client.list_groups(namespace).expect("list groups");
    println!("List groups: {:?}", groups);
}
