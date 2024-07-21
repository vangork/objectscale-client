use objectscale_client::client::ManagementClient;
use objectscale_client::iam::RolePolicyAttachmentBuilder;

fn main() {
    let endpoint = "https://10.225.108.189:443";
    let username = "root";
    let password = "Password123@";
    let insecure = true;

    let role_name = "r1";
    let arn = "urn:osc:iam:::policy/CRRFullAccess";
    //let arn = "urn:osc:iam:::policy/CRRSameAccountFullAccess";
    let namespace = "osai0a9250592a131336";

    let mut client: ManagementClient =
        ManagementClient::new(endpoint, username, password, insecure).expect("management client");
    let role_policy_attachment = RolePolicyAttachmentBuilder::default()
        .role_name(role_name)
        .policy_arn(arn)
        .namespace(namespace)
        .build()
        .expect("role policy attachment");

    let role_policy_attachment = client
        .create_role_policy_attachment(role_policy_attachment)
        .expect("create role policy attachment");
    println!(
        "Created role policy attachment: {:?}",
        role_policy_attachment
    );

    let role_policy_attachments = client
        .list_role_policy_attachments(role_name, namespace)
        .expect("list role policy attachment");
    println!(
        "List role policy attachments: {:?}",
        role_policy_attachments
    );

    client
        .delete_role_policy_attachment(role_policy_attachment)
        .expect("delete role policy attachment");
    println!("Deleted role policy attachment");

    let role_policy_attachments = client
        .list_role_policy_attachments(role_name, namespace)
        .expect("list role policy attachment");
    println!(
        "List role policy attachments: {:?}",
        role_policy_attachments
    );
}
