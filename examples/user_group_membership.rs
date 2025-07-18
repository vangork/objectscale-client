use objectscale_client::client::ManagementClient;
use objectscale_client::iam::UserGroupMembershipBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let group_name = "g1";
    let user_name = "luis";
    let namespace = "osai0a9250592a131336";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let user_group_membership = UserGroupMembershipBuilder::default()
        .user_name(user_name)
        .group_name(group_name)
        .namespace(namespace)
        .build()
        .expect("user group membership");

    let user_group_membership = client
        .create_user_group_membership(user_group_membership)
        .expect("create user group membership");
    println!("Created user group membership: {:?}", user_group_membership);

    let user_group_memberships = client
        .list_user_group_memberships_by_user(user_name, namespace)
        .expect("list user group membership");
    println!("List user group memberships: {:?}", user_group_memberships);

    let user_group_memberships = client
        .list_user_group_memberships_by_group(group_name, namespace)
        .expect("list user group membership");
    println!("List user group memberships: {:?}", user_group_memberships);

    client
        .delete_user_group_membership(user_group_membership)
        .expect("delete user group membership");
    println!("Deleted user group membership");

    let user_group_memberships = client
        .list_user_group_memberships_by_user(user_name, namespace)
        .expect("list user group membership");
    println!("List user group memberships: {:?}", user_group_memberships);

    let user_group_memberships = client
        .list_user_group_memberships_by_group(group_name, namespace)
        .expect("list user group membership");
    println!("List user group memberships: {:?}", user_group_memberships);
}
