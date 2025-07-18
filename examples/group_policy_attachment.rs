use objectscale_client::client::ManagementClient;
use objectscale_client::iam::GroupPolicyAttachmentBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let group_name = "g1";
    let arn = "urn:osc:iam:::policy/CRRFullAccess";
    //let arn = "urn:osc:iam:::policy/CRRSameAccountFullAccess";
    let namespace = "osai0a9250592a131336";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let group_policy_attachment = GroupPolicyAttachmentBuilder::default()
        .group_name(group_name)
        .policy_arn(arn)
        .namespace(namespace)
        .build()
        .expect("group policy attachment");

    let group_policy_attachment = client
        .create_group_policy_attachment(group_policy_attachment)
        .expect("create group policy attachment");
    println!(
        "Created group policy attachment: {:?}",
        group_policy_attachment
    );

    let group_policy_attachments = client
        .list_group_policy_attachments(group_name, namespace)
        .expect("list group policy attachment");
    println!(
        "List group policy attachments: {:?}",
        group_policy_attachments
    );

    client
        .delete_group_policy_attachment(group_policy_attachment)
        .expect("delete group policy attachment");
    println!("Deleted group policy attachment");

    let group_policy_attachments = client
        .list_group_policy_attachments(group_name, namespace)
        .expect("list group policy attachment");
    println!(
        "List group policy attachments: {:?}",
        group_policy_attachments
    );
}
